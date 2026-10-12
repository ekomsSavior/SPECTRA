#!/usr/bin/env python3
from pathlib import Path
import subprocess,sys
root=Path(__file__).resolve().parents[1]
checks=['code-continuation.test.cjs','arm-pie.test.cjs','runtime.test.cjs','deep-analysis.test.cjs','library.test.cjs','lab-forms.test.cjs','navigation.test.cjs','squashfs.test.cjs','system.test.cjs','analysis.test.cjs','detection.test.cjs','downloads.test.mjs','recovery.test.cjs','debugger.test.cjs','windows.test.cjs','edge.test.mjs','native.test.mjs','hardware.test.mjs','hardware-debugger.test.cjs','advanced-lab.test.cjs','experiments.test.cjs','project.test.cjs','firmware.test.cjs','compare.test.cjs','managed.test.mjs','managed-worker.test.mjs','dependencies.test.mjs','harness.test.mjs']
for name in checks:
 result=subprocess.run(['node',str(root/'tests'/name)],cwd=root)
 if result.returncode:sys.exit(result.returncode)
