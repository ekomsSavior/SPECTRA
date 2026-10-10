# Build the Church's RE workbench

SPECTRA stays free: the same core tools for learners and professionals, usable offline and without sample uploads. Contributions should make an investigation easier to repeat and easier to check.

Open an issue or pull request at https://git.churchofmalware.org/ek0mssavi0r/SPECTRA with the research task, observed behavior, expected behavior and relevant limits. Do not attach live malware or private samples publicly. Prefer a tiny benign reproducer with source, compiler/architecture/ABI, exact bytes/hash, expected observations and an explanation of what the test does not establish.

For a lesson, include source and compiled fixture/build recipe, a starting question, optional hint, walkthrough, and an evidence-based check. Keep the explanation specific and human. Existing lessons are in `src/lessons-ui.js` and fixtures/tests.

For parser/engine changes, test malformed/truncated input, budgets/cancellation, real instruction behavior and architecture assumptions. Do not invent successful API results or hide heuristic uncertainty. Native execution belongs in an explicit analyst-controlled environment. Match new dependencies with their exact license/provenance/source obligations. Add no paid API requirement, remote sample processing or tracking.

Keep the interface black, gray and white. Every new control needs a label, keyboard access and a useful state/error message. Keep optional explanations optional. Document exported formats and preserve a practical migration path.

Run `python3 scripts/test.py`; use the documented optional harness/companion checks where affected. Inspect the actual browser at desktop and narrow widths. Include measurements when changing large WASM assets or memory-heavy workflows. Security reports should omit sensitive data from public issues; contact the Church through its established private contact channel for disclosure.
