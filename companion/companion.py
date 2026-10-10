#!/usr/bin/env python3
"""SPECTRA experimental Linux GDB/MI companion. Local browser UI.

One target is chosen at startup. Loading parses it; launch explicitly executes real
native code. This is not a sandbox. No debugger console/evaluate endpoint exists.
"""
from __future__ import annotations
import argparse
import collections
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import threading
import time

MAX_LINE = 1024 * 1024
MAX_BODY = 16384

class MIError(Exception):
    pass


def mi_quote(value: str) -> str:
    """Quote one MI C-string argument, using UTF-8 bytes and octal escapes."""
    result = ['"']
    for byte in value.encode('utf-8'):
        if byte in (34, 92):
            result.append('\\' + chr(byte))
        elif 32 <= byte < 127:
            result.append(chr(byte))
        else:
            result.append('\\%03o' % byte)
    return ''.join(result) + '"'


class MIParser:
    def __init__(self, text):
        if len(text) > MAX_LINE:
            raise MIError('MI record too large')
        self.s, self.i, self.nodes = text, 0, 0

    def char(self):
        return self.s[self.i:self.i + 1]

    def expect(self, c):
        if self.char() != c:
            raise MIError('Malformed MI delimiter')
        self.i += 1

    def word(self):
        match = re.match(r'[A-Za-z_][A-Za-z0-9_-]*', self.s[self.i:])
        if not match:
            raise MIError('Malformed MI name')
        self.i += len(match[0])
        return match[0]

    def string(self):
        self.expect('"')
        out = bytearray()
        escapes = {'a': 7, 'b': 8, 't': 9, 'n': 10, 'v': 11, 'f': 12, 'r': 13,
                   'e': 27, '\\': 92, '"': 34, "'": 39, '?': 63}
        while self.i < len(self.s):
            c = self.s[self.i]
            self.i += 1
            if c == '"':
                return out.decode('utf-8', 'replace')
            if c != '\\':
                out.extend(c.encode('utf-8'))
                continue
            if self.i == len(self.s):
                raise MIError('Truncated MI escape')
            c = self.s[self.i]
            self.i += 1
            if c in escapes:
                out.append(escapes[c])
            elif c in '01234567':
                digits = c
                while len(digits) < 3 and self.char() and self.char() in '01234567':
                    digits += self.char()
                    self.i += 1
                n = int(digits, 8)
                if n > 255:
                    raise MIError('Invalid MI octal byte')
                out.append(n)
            elif c == 'x':
                match = re.match(r'[a-fA-F0-9]{1,2}', self.s[self.i:])
                if not match:
                    raise MIError('Invalid MI hex escape')
                out.append(int(match[0], 16))
                self.i += len(match[0])
            else:
                raise MIError('Unsupported MI escape')
        raise MIError('Unterminated MI string')

    def result(self, depth):
        key = self.word()
        self.expect('=')
        return key, self.value(depth + 1)

    def value(self, depth=0):
        self.nodes += 1
        if depth > 32 or self.nodes > 10000:
            raise MIError('MI structure limit')
        if self.char() == '"':
            return self.string()
        if self.char() == '{':
            self.i += 1
            out = {}
            if self.char() != '}':
                while True:
                    key, value = self.result(depth)
                    if key in out:
                        raise MIError('Duplicate MI tuple field')
                    out[key] = value
                    if self.char() != ',':
                        break
                    self.i += 1
            self.expect('}')
            return out
        if self.char() == '[':
            self.i += 1
            out = []
            if self.char() != ']':
                while True:
                    if re.match(r'[A-Za-z_][A-Za-z0-9_-]*=', self.s[self.i:]):
                        key, value = self.result(depth)
                        out.append({key: value})
                    else:
                        out.append(self.value(depth + 1))
                    if self.char() != ',':
                        break
                    self.i += 1
            self.expect(']')
            return out
        raise MIError('Invalid MI value')

    def record(self):
        if self.s.strip() == '(gdb)':
            return {'kind': 'prompt'}
        token = None
        match = re.match(r'[0-9]+', self.s)
        if match:
            if len(match[0]) > 12:
                raise MIError('MI token limit')
            token = int(match[0])
            self.i = len(match[0])
        kind = self.char()
        if kind not in ('^', '*', '+', '=', '~', '@', '&'):
            return {'kind': 'diagnostic', 'text': self.s[:2048]}
        self.i += 1
        if kind in ('~', '@', '&'):
            result = {'kind': kind, 'text': self.string()}
        else:
            result = {'kind': kind, 'class': self.word(), 'results': {}}
            while self.char() == ',':
                self.i += 1
                key, value = self.result(0)
                if key in result['results']:
                    raise MIError('Duplicate MI result field')
                result['results'][key] = value
        if self.i != len(self.s):
            raise MIError('Trailing MI data')
        if token is not None:
            result['token'] = token
        return result


def parse_mi(line):
    return MIParser(line.rstrip('\r\n')).record()


def integer(value, low, high, name):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f'{name} must be an integer from {low} to {high}')
    return value


def address(value):
    if not isinstance(value, str) or not re.fullmatch(r'0x[0-9a-fA-F]{1,16}', value):
        raise ValueError('Address must be a hexadecimal integer, not an expression')
    return '0x%x' % int(value, 16)


class DebugSession:
    def __init__(self, target: Path):
        target = target.resolve(strict=True)
        if not target.is_file() or target.stat().st_size > 64 * 1024 * 1024:
            raise ValueError('Choose a regular local executable of at most 64 MiB')
        self.target = target
        self.target_hash = hashlib.sha256(target.read_bytes()).hexdigest()
        self.cv = threading.Condition(threading.RLock())
        self.operation = threading.Lock()
        self.send_lock = threading.Lock()
        self.next_token = 1
        self.pending = {}
        self.state = 'unloaded'
        self.closed = False
        self.events = collections.deque(maxlen=128)
        self.sequence = 0
        self.register_names = None
        self.tty_master, self.tty_slave = os.openpty()
        # Separate inferior output from the MI control channel: target text cannot
        # impersonate a ^done or *stopped debugger record.
        self.process = subprocess.Popen(
            ['gdb', '--nx', '--nh', '--quiet', '--interpreter=mi2',
             '-iex', 'set auto-load off', '-iex', 'set debuginfod enabled off'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=True, bufsize=0, cwd=str(target.parent))
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        self.tty_reader = threading.Thread(target=self._read_tty, daemon=True)
        self.tty_reader.start()
        try:
            for command in ['-gdb-set mi-async on', '-gdb-set pagination off',
                            '-gdb-set confirm off', '-gdb-set startup-with-shell off',
                            '-gdb-set print raw-values on', '-gdb-set print elements 64',
                            '-gdb-set print repeats 16',
                            '-inferior-tty-set ' + mi_quote(os.ttyname(self.tty_slave))]:
                self._command(command)
        except Exception:
            self.close()
            raise

    def _event(self, record):
        # Called under cv, or acquire it via Condition's RLock.
        with self.cv:
            if len(json.dumps(record, ensure_ascii=True)) > 16384:
                record = {'kind': record.get('kind', 'diagnostic'), 'class': record.get('class', ''), 'truncated': True}
            self.sequence += 1
            self.events.append({'sequence': self.sequence, **record})
            self.cv.notify_all()

    def _read(self):
        try:
            while True:
                raw = self.process.stdout.readline(MAX_LINE + 1)
                if not raw:
                    break
                if len(raw) > MAX_LINE:
                    raise MIError('GDB exceeded its output limit')
                record = parse_mi(raw.decode('utf-8', 'replace'))
                with self.cv:
                    if record['kind'] == '^':
                        token = record.get('token')
                        if token in self.pending:
                            self.pending[token] = record
                            self.cv.notify_all()
                    elif record['kind'] == '*':
                        if record['class'] == 'running':
                            self.state = 'running'
                        elif record['class'] == 'stopped':
                            reason = record['results'].get('reason', '')
                            self.state = 'exited' if reason.startswith('exited') else 'stopped'
                        self._event(record)
                    elif record['kind'] in ('=', '~', '@', '&', 'diagnostic'):
                        if 'text' in record:
                            record['text'] = record['text'][:2048]
                        self._event(record)
        except (OSError, MIError) as error:
            with self.cv:
                self._event({'kind': 'error', 'message': str(error)})
            self.process.kill()
        finally:
            with self.cv:
                if not self.closed:
                    self.state = 'failed'
                self.cv.notify_all()

    def _read_tty(self):
        try:
            while not self.closed:
                data = os.read(self.tty_master, 2048)
                if not data:
                    break
                self._event({'kind': 'target-output', 'text': data.decode('utf-8', 'replace')})
        except OSError:
            pass

    def _command(self, command, timeout=8):
        if '\n' in command or '\r' in command or not command.startswith('-'):
            raise ValueError('Invalid internal MI command')
        with self.cv:
            if self.closed:
                raise MIError('Session is closed')
            token = self.next_token
            self.next_token += 1
            self.pending[token] = None
        try:
            with self.send_lock:
                self.process.stdin.write((str(token) + command + '\n').encode('ascii'))
                self.process.stdin.flush()
            with self.cv:
                deadline = time.monotonic() + timeout
                while self.pending[token] is None:
                    if self.process.poll() is not None or self.state == 'failed':
                        raise MIError('Debugger exited')
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('Debugger command timed out; close the session')
                    self.cv.wait(remaining)
                result = self.pending[token]
            if result['class'] == 'error':
                raise MIError(result['results'].get('msg', 'Debugger rejected operation'))
            return result
        finally:
            with self.cv:
                self.pending.pop(token, None)

    def snapshot(self, after=0):
        with self.cv:
            return {'state': self.state, 'sequence': self.sequence,
                    'events': [event for event in self.events if event['sequence'] > after],
                    'eventsTruncated': bool(self.events and after < self.events[0]['sequence'] - 1),
                    'target': self.target.name, 'sha256': self.target_hash,
                    'capabilities': ['load', 'launch-stop-at-main', 'step-instruction',
                                     'next-instruction', 'finish', 'pause', 'continue',
                                     'stack', 'registers', 'memory-read', 'breakpoint',
                                     'breakpoint-delete', 'threads', 'quit']}

    def handle(self, request):
        if not isinstance(request, dict) or not isinstance(request.get('op'), str):
            raise ValueError('Expected an operation object')
        op = request['op']
        fields = {'status': {'after'}, 'load': set(), 'launch': set(), 'step': set(),
                  'next': set(), 'finish': set(), 'pause': set(), 'continue': set(),
                  'stack': set(), 'registers': {'indices'}, 'memory': {'address', 'length'},
                  'breakpoint': {'address'}, 'breakpoint_delete': {'id'}, 'threads': set(),
                  'quit': set()}
        if op not in fields or set(request) - {'op'} - fields.get(op, set()):
            raise ValueError('Unsupported operation or fields')
        with self.operation:
            if op == 'status':
                return self.snapshot(integer(request.get('after', 0), 0, 2**53 - 1, 'after'))
            if op == 'quit':
                self.close()
                return self.snapshot()
            with self.cv:
                current = self.state
            if op == 'load':
                if current not in ('unloaded', 'loaded', 'exited'):
                    raise ValueError('Load requires no running target')
                # Detect target replacement since startup, before handing it to GDB.
                if hashlib.sha256(self.target.read_bytes()).hexdigest() != self.target_hash:
                    raise ValueError('Selected target changed; start a new session')
                result = self._command('-file-exec-and-symbols ' + mi_quote(str(self.target)))
                with self.cv:
                    self.state = 'loaded'
                    self.register_names = None
            elif op == 'launch':
                if current != 'loaded':
                    raise ValueError('Load the target before launching')
                if hashlib.sha256(self.target.read_bytes()).hexdigest() != self.target_hash:
                    raise ValueError('Selected target changed since pairing; start a new session')
                result = self._command('-exec-run --start')
            elif op == 'pause':
                if current != 'running':
                    raise ValueError('Target is not running')
                result = self._command('-exec-interrupt --all')
            elif op in ('step', 'next', 'finish', 'continue'):
                if current != 'stopped':
                    raise ValueError('Target must be stopped')
                commands = {'step': '-exec-step-instruction', 'next': '-exec-next-instruction',
                            'finish': '-exec-finish', 'continue': '-exec-continue'}
                result = self._command(commands[op])
            elif op == 'breakpoint':
                if current not in ('loaded', 'stopped'):
                    raise ValueError('Load or stop target before setting a breakpoint')
                result = self._command('-break-insert *' + address(request.get('address')))
            elif op == 'breakpoint_delete':
                if current not in ('loaded', 'stopped'):
                    raise ValueError('Load or stop target before deleting a breakpoint')
                result = self._command('-break-delete ' + str(integer(request.get('id'), 1, 100000, 'id')))
            else:
                if current != 'stopped':
                    raise ValueError('Target must be stopped for inspection')
                if op == 'stack':
                    result = self._command('-stack-list-frames 0 31')
                elif op == 'threads':
                    result = self._command('-thread-info')
                elif op == 'memory':
                    addr = address(request.get('address'))
                    count = integer(request.get('length'), 1, 4096, 'length')
                    if int(addr, 16) + count > 2**64:
                        raise ValueError('Memory range overflows address space')
                    result = self._command(f'-data-read-memory-bytes {addr} {count}')
                elif op == 'registers':
                    if self.register_names is None:
                        self.register_names = self._command('-data-list-register-names')['results']['register-names']
                    indices = request.get('indices', list(range(min(32, len(self.register_names)))))
                    if not isinstance(indices, list) or not 1 <= len(indices) <= 64:
                        raise ValueError('Choose 1 to 64 register indices')
                    for index in indices:
                        integer(index, 0, len(self.register_names) - 1, 'register index')
                    result = self._command('-data-list-register-values --skip-unavailable x ' + ' '.join(map(str, indices)))
                    result['names'] = {str(index): self.register_names[index] for index in indices}
                else:
                    raise ValueError('Unsupported operation')
            return {'result': result, **self.snapshot()}

    def close(self):
        if self.closed:
            return
        try:
            if self.process.poll() is None:
                self._command('-gdb-exit', timeout=3)
        except Exception:
            if self.process.poll() is None:
                self.process.kill()
        finally:
            with self.cv:
                self.closed = True
                self.state = 'closed'
                self.cv.notify_all()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
            for descriptor in (self.tty_master, self.tty_slave):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            for pipe in (self.process.stdin, self.process.stdout):
                try:
                    pipe.close()
                except (OSError, ValueError):
                    pass


def unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON field')
        result[key] = value
    return result


class LocalServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, target):
        self.token = secrets.token_urlsafe(32)
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(('127.0.0.1', 0), Handler)
        self.authority = '127.0.0.1:' + str(self.server_address[1])
        self.origin = 'http://' + self.authority
        try:
            self.session = DebugSession(Path(target))
        except Exception:
            self.server_close()
            raise

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def close(self):
        self.session.close()
        self.shutdown()
        self.server_close()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'SPECTRA-research'

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_):
        pass  # Do not log pairing credentials or target paths.

    def reply(self, code, data):
        encoded = json.dumps(data, ensure_ascii=True).encode('ascii')
        if len(encoded) > MAX_LINE:
            code, encoded = 502, b'{"error":"Response exceeded limit"}'
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(encoded)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Connection', 'close')
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(encoded)
        self.close_connection = True

    def authorize(self):
        if self.headers.get_all('Host') != [self.server.authority]:
            self.reply(403, {'error': 'Host rejected'})
            return False
        if self.headers.get_all('Origin') != [self.server.origin]:
            self.reply(403, {'error': 'Origin rejected'})
            return False
        values = self.headers.get_all('Authorization')
        expected = 'Bearer ' + self.server.token
        if not values or len(values) != 1 or not values[0].isascii() or not secrets.compare_digest(values[0], expected):
            self.reply(401, {'error': 'Pairing token required'})
            return False
        return True

    def do_POST(self):
        if not self.authorize():
            return
        if self.path != '/api':
            self.reply(404, {'error': 'Unknown endpoint'})
            return
        if self.headers.get('Transfer-Encoding') is not None:
            self.reply(400, {'error': 'Transfer encoding unsupported'})
            return
        lengths = self.headers.get_all('Content-Length')
        if not lengths or len(lengths) != 1 or not re.fullmatch(r'[0-9]{1,6}', lengths[0]):
            self.reply(400, {'error': 'One bounded Content-Length is required'})
            return
        length = int(lengths[0])
        if not 1 <= length <= MAX_BODY:
            self.reply(413, {'error': 'Request exceeds limit'})
            return
        if self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/json':
            self.reply(415, {'error': 'Use application/json'})
            return
        try:
            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError('Truncated body')
            value = json.loads(body, object_pairs_hook=unique_json,
                               parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON number')))
            self.reply(200, self.server.session.handle(value))
        except (ValueError, KeyError, RecursionError) as error:
            self.reply(400, {'error': str(error)[:512]})
        except MIError as error:
            self.reply(409, {'error': str(error)[:512]})
        except TimeoutError:
            self.server.session.close()
            self.reply(504, {'error': 'Debugger timeout; session closed'})
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def do_GET(self):
        if self.headers.get_all('Host') != [self.server.authority]:
            self.reply(403, {'error': 'Host rejected'})
            return
        files = {'/': ('index.html', 'text/html; charset=utf-8'), '/companion.js': ('companion.js', 'text/javascript; charset=utf-8')}
        if self.command != 'GET' or self.path not in files:
            self.reply(405, {'error': 'POST /api with local Origin and pairing token'})
            return
        name, mime = files[self.path]
        body = Path(__file__).with_name(name).read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    do_OPTIONS = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_HEAD = do_GET


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True, type=Path)
    args = parser.parse_args()
    server = LocalServer(args.target)
    print('Open local SPECTRA debugger: ' + server.origin + '/', flush=True)
    print('Pairing token: ' + server.token, flush=True)
    print('Target is not loaded or launched. Native execution is real; use a lab.', flush=True)
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        server.session.close()
        server.server_close()


if __name__ == '__main__':
    main()
