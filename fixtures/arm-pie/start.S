/* Benign ARM EABI static-PIE fixture. Synthetic layout supplied by make-fixtures.py.
 * _start relocates a data pointer once, then writes "pie\n" and exits.
 * The alternate entry expects the debugger to have applied its REL record.
 */
.syntax unified
.arm
.global _start
_start:
.Lbegin:
 adr r4, .Lbegin
 sub r4, r4, #0x100
 add r5, r4, #0x1000
 ldr r6, [r5]
 add r6, r6, r4
 str r6, [r5]
 b alternate
.org 0x80
alternate:
 adr r4, alternate
 sub r4, r4, #0x180
 add r5, r4, #0x1000
 ldr r1, [r5]
 mov r0, #1
 mov r2, #4
 mov r7, #4
 svc #0
 mov r0, #0
 mov r7, #1
 svc #0
.org 0xc0
svc_test:
 svc #0
 mrc p15, 0, r0, c13, c0, 3
