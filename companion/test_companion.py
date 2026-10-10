#!/usr/bin/env python3
import http.client
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import threading
import time
import unittest

from companion import LocalServer, MIError, mi_quote, parse_mi

ROOT = Path(__file__).resolve().parent
LAB = ROOT / 'lab target "quoted"; literal'
TARGET = LAB / 'benign-client'

FIXTURE = r'''
#include <stdio.h>
#include <unistd.h>
volatile unsigned int counter = 0x11223344;
const char known_message[] = "SPECTRA benign debugger fixture";
__attribute__((constructor)) static void init_marker(void) {
    FILE *file = fopen("execution.marker", "w");
    if (file) { fputs("benign constructor executed", file); fclose(file); }
    puts("999^exit\n*running,thread-id=\"spoofed-by-target\"\nhello, \"MI\" \\ bytes");
    fflush(stdout);
}
__attribute__((noinline)) unsigned int helper(unsigned int value) { return value + 3; }
int main(void) {
    counter += helper(4);
    while (access("stop.marker", F_OK) != 0) usleep(1000);
    return 0;
}
'''


def compile_fixture():
    LAB.mkdir(exist_ok=True)
    (LAB / 'fixture.c').write_text(FIXTURE)
    for name in ['execution.marker', 'stop.marker', 'gdbinit.marker', 'autoload.marker']:
        (LAB / name).unlink(missing_ok=True)
    # These are benign sentinels that must remain unexecuted during loading.
    (LAB / '.gdbinit').write_text('shell touch gdbinit.marker\n')
    Path(str(TARGET) + '-gdb.py').write_text("open('autoload.marker', 'w').write('unexpected')\n")
    subprocess.run(['gcc', '-g', '-O0', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie',
                    str(LAB / 'fixture.c'), '-o', str(TARGET)], check=True)
    text = subprocess.run(['nm', '-n', str(TARGET)], check=True, capture_output=True, text=True).stdout
    return {line.split()[2]: '0x' + line.split()[0] for line in text.splitlines() if len(line.split()) == 3}


class ParserTests(unittest.TestCase):
    def test_cstring_roundtrip(self):
        for value in ['plain', 'quote " slash \\ newline\n return\r tab\t', 'é 漢字', 'a\x00b', '; -exec-run\n999-exec-run']:
            quoted = mi_quote(value)
            self.assertNotIn('\n', quoted)
            self.assertEqual(parse_mi('7^done,value=' + quoted)['results']['value'], value)

    def test_nested_lists_and_repeated_result_names(self):
        record = parse_mi('23^done,stack=[frame={level="0",func="f, x",args=[{name="a",value="\\\"hi\\\""}]},frame={level="1",func="main"}],bytes=["one","two"]')
        self.assertEqual(record['token'], 23)
        self.assertEqual(record['results']['stack'][0]['frame']['args'][0]['value'], '"hi"')
        self.assertEqual(record['results']['stack'][1]['frame']['func'], 'main')
        self.assertEqual(record['results']['bytes'], ['one', 'two'])

    def test_stream_and_async(self):
        self.assertEqual(parse_mi('~"hello\\n\\303\\251"')['text'], 'hello\né')
        self.assertEqual(parse_mi('*stopped,reason="breakpoint-hit",frame={addr="0x1234"}')['class'], 'stopped')
        self.assertEqual(parse_mi('(gdb)')['kind'], 'prompt')

    def test_malformed_and_bounded(self):
        for line in ['1^done,x="unterminated', '1^done,x="a",x="b"', '1^done,x={x="a",x="b"}',
                     '1^done,x="a"garbage', '1^done,x=' + '[' * 40 + '"x"' + ']' * 40,
                     '1^done,x="\\777"']:
            with self.assertRaises(MIError, msg=line):
                parse_mi(line)


class CompanionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.symbols = compile_fixture()
        cls.server = LocalServer(TARGET)
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
        cls.thread.start()
        cls.gdb_pid = cls.server.session.process.pid

    @classmethod
    def tearDownClass(cls):
        cls.server.close()
        cls.thread.join(timeout=3)

    def call(self, data, headers=None, raw_body=None, expected=200, method='POST', path='/api'):
        body = json.dumps(data).encode() if raw_body is None else raw_body
        hs = {'Host': self.server.authority, 'Origin': self.server.origin,
              'Authorization': 'Bearer ' + self.server.token, 'Content-Type': 'application/json'}
        for key, value in (headers or {}).items():
            if value is None:
                hs.pop(key, None)
            else:
                hs[key] = value
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_address[1], timeout=12)
        connection.request(method, path, body, hs)
        response = connection.getresponse()
        output = json.loads(response.read())
        self.assertEqual(response.status, expected, output)
        self.assertIsNone(response.getheader('Access-Control-Allow-Origin'))
        self.assertEqual(response.getheader('Cache-Control'), 'no-store')
        connection.close()
        return output

    def wait_for(self, predicate, after=0):
        deadline = time.monotonic() + 5
        result = None
        while time.monotonic() < deadline:
            result = self.call({'op': 'status', 'after': after})
            if predicate(result):
                return result
            time.sleep(.01)
        self.fail('Timed out waiting for debugger state: ' + json.dumps(result))

    def stopped_after(self, before):
        return self.wait_for(lambda r: r['state'] in ('stopped', 'exited') and any(e.get('kind') == '*' and e.get('class') == 'stopped' for e in r['events']), before)

    def test_01_host_origin_token_and_headers(self):
        self.assertEqual(self.server.server_address[0], '127.0.0.1')
        self.assertGreaterEqual(len(self.server.token), 40)
        for headers, expected in [({'Host': 'evil.example'}, 403), ({'Host': 'localhost:' + str(self.server.server_address[1])}, 403),
                                  ({'Origin': 'https://evil.example'}, 403), ({'Origin': 'null'}, 403),
                                  ({'Origin': None}, 403), ({'Authorization': 'Bearer wrong'}, 401),
                                  ({'Authorization': None}, 401)]:
            self.call({'op': 'status'}, headers, expected=expected)
        self.call({'op': 'status'}, method='OPTIONS', expected=405)
        self.call({'op': 'status'}, path='/api?token=not-used', expected=404)
        self.call({}, raw_body=b'{"op":"status","op":"launch"}', expected=400)
        self.call({}, headers={'Content-Type': 'text/plain'}, expected=415)
        self.call({}, raw_body=b'x' * 16385, expected=413)
        # Duplicate Host is rejected instead of picking a convenient first/last value.
        with socket.create_connection(self.server.server_address, timeout=3) as client:
            raw = (f'POST /api HTTP/1.1\r\nHost: {self.server.authority}\r\nHost: evil.example\r\n'
                   f'Origin: {self.server.origin}\r\nAuthorization: Bearer {self.server.token}\r\n'
                   'Content-Length: 15\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{"op":"status"}').encode()
            client.sendall(raw)
            self.assertTrue(client.recv(4096).startswith(b'HTTP/1.1 403'))

    def test_02_load_only_and_no_arbitrary_commands(self):
        start = self.call({'op': 'status'})
        self.assertEqual(start['state'], 'unloaded')
        self.assertFalse((LAB / 'execution.marker').exists())
        before = self.server.session.next_token
        for request in [{'op': 'console', 'command': 'shell touch bad'}, {'op': 'evaluate', 'expression': 'helper(4)'},
                        {'op': 'load', 'path': '/bin/sh'}, {'op': 'launch', 'args': ['injected']}]:
            self.call(request, expected=400)
        self.assertEqual(self.server.session.next_token, before)
        loaded = self.call({'op': 'load'})
        self.assertEqual(loaded['state'], 'loaded')
        self.assertFalse((LAB / 'execution.marker').exists())
        self.assertFalse((LAB / 'gdbinit.marker').exists())
        self.assertFalse((LAB / 'autoload.marker').exists())
        self.call({'op': 'memory', 'address': self.symbols['counter'], 'length': 4}, expected=400)
        self.call({'op': 'step'}, expected=400)

    def test_03_launch_and_real_memory_registers(self):
        before = self.call({'op': 'status'})['sequence']
        self.call({'op': 'launch'})
        stopped = self.stopped_after(before)
        self.assertEqual(stopped['state'], 'stopped')
        self.assertTrue((LAB / 'execution.marker').exists())
        frames = self.call({'op': 'stack'})['result']['results']['stack']
        self.assertEqual(frames[0]['frame']['func'], 'main')
        data = self.call({'op': 'memory', 'address': self.symbols['counter'], 'length': 4})['result']['results']['memory']
        self.assertEqual(data[0]['contents'], '44332211')
        registers = self.call({'op': 'registers'})['result']
        self.assertIn('rip', registers['names'].values())
        self.assertGreater(len(registers['results']['register-values']), 10)
        threads = self.call({'op': 'threads'})['result']['results']['threads']
        self.assertGreaterEqual(len(threads), 1)
        # Target output looking like MI is captured on a separate PTY, never parsed.
        output = self.wait_for(lambda r: any(e.get('kind') == 'target-output' and '999^exit' in e.get('text', '') for e in r['events']))
        self.assertEqual(output['state'], 'stopped')
        self.assertFalse(any(e.get('kind') == '*' and e.get('results', {}).get('thread-id') == 'spoofed-by-target' for e in output['events']))

    def test_04_validation_rejects_expressions_and_oversized_reads(self):
        before = self.server.session.next_token
        requests = [{'op': 'memory', 'address': 'helper(4)', 'length': 4},
                    {'op': 'memory', 'address': '0x1\n-exec-run', 'length': 4},
                    {'op': 'memory', 'address': '0x1000', 'length': 4097},
                    {'op': 'memory', 'address': '0xffffffffffffffff', 'length': 2},
                    {'op': 'memory', 'address': '0x1000', 'length': True},
                    {'op': 'breakpoint', 'address': 'main; shell touch bad'},
                    {'op': 'breakpoint_delete', 'id': '1 -exec-run'},
                    {'op': 'registers', 'indices': [False]}, {'op': 'registers', 'indices': list(range(65))}]
        for request in requests:
            self.call(request, expected=400)
        self.assertEqual(self.server.session.next_token, before)
        self.call({'op': 'memory', 'address': '0x1', 'length': 4}, expected=409)

    def test_05_instruction_step_next_breakpoint_finish(self):
        def pc():
            values = self.call({'op': 'registers'})['result']
            index = next(i for i, name in values['names'].items() if name == 'rip')
            return next(v['value'] for v in values['results']['register-values'] if v['number'] == index)
        inserted = self.call({'op': 'breakpoint', 'address': self.symbols['helper']})
        identifier = int(inserted['result']['results']['bkpt']['number'])
        old_pc = pc()
        before = self.call({'op': 'status'})['sequence']
        self.call({'op': 'step'})
        self.stopped_after(before)
        self.assertNotEqual(pc(), old_pc)
        old_pc = pc()
        before = self.call({'op': 'status'})['sequence']
        self.call({'op': 'next'})
        self.stopped_after(before)
        self.assertNotEqual(pc(), old_pc)
        paused = self.call({'op': 'status'})
        # A step-over must still honor a breakpoint inside the called function.
        # If the compiler emitted another instruction first, continue to that breakpoint.
        if self.call({'op': 'stack'})['result']['results']['stack'][0]['frame']['func'] != 'helper':
            before = paused['sequence']
            self.call({'op': 'continue'})
            paused = self.stopped_after(before)
        frames = self.call({'op': 'stack'})['result']['results']['stack']
        self.assertEqual(frames[0]['frame']['func'], 'helper')
        self.call({'op': 'breakpoint_delete', 'id': identifier})
        before = paused['sequence']
        self.call({'op': 'finish'})
        result = self.stopped_after(before)
        self.assertTrue(any(e.get('results', {}).get('reason') == 'function-finished' for e in result['events']))
        self.assertEqual(self.call({'op': 'stack'})['result']['results']['stack'][0]['frame']['func'], 'main')

    def test_06_pause_continue_normal_exit(self):
        self.call({'op': 'continue'})
        running = self.wait_for(lambda r: r['state'] == 'running')
        self.call({'op': 'pause'})
        result = self.stopped_after(running['sequence'])
        self.assertEqual(result['state'], 'stopped')
        data = self.call({'op': 'memory', 'address': self.symbols['counter'], 'length': 4})['result']['results']['memory']
        self.assertEqual(data[0]['contents'], '4b332211')
        (LAB / 'stop.marker').write_text('fixture may exit')
        before = result['sequence']
        self.call({'op': 'continue'})
        result = self.stopped_after(before)
        self.assertEqual(result['state'], 'exited')

    def test_07_quit_terminates_a_running_inferior(self):
        (LAB / 'stop.marker').unlink()
        self.call({'op': 'load'})
        before = self.call({'op': 'status'})['sequence']
        self.call({'op': 'launch'})
        self.stopped_after(before)
        self.call({'op': 'continue'})
        running = self.wait_for(lambda r: r['state'] == 'running')
        starts = [e for e in running['events'] if e.get('kind') == '=' and e.get('class') == 'thread-group-started']
        pid = int(starts[-1]['results']['pid'])
        result = self.call({'op': 'quit'})
        self.assertEqual(result['state'], 'closed')
        self.assertIsNotNone(self.server.session.process.poll())
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and Path('/proc/' + str(pid)).exists():
            time.sleep(.01)
        self.assertFalse(Path('/proc/' + str(pid)).exists(), 'Inferior survived quit')


if __name__ == '__main__':
    unittest.main(verbosity=2)
