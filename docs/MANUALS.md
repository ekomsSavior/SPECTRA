# Published SPECTRA field manuals

The Training ground begins with **RE for beginners with SPECTRA** (33 chapters, 91 PDF pages) and **Intermediate RE with SPECTRA** (22 chapters, 76 pages). Edition 2 is dated 10 November 2026 and describes the SPECTRA 0.18 workbench, including Android analysis, recordings, evidence bundles, address mapping, routine history and all forty stages across six Church CTF campaigns.

The editable HTML, print PDFs, reading assets and benign practice files live in `manuals/`. The original control-by-control field guide remains available below the manuals. `manuals/practice/manifest.json` records fixture sizes and SHA-256 hashes. Practice files are teaching artifacts; no live malware is bundled.

`node build.mjs` and `node build.mjs --html-only` both copy the manuals into `dist/manuals/` and generate `manual-paths.mjs`. The edge worker allows those exact paths, including Cloudflare's clean HTML URLs. The books use a separate restrictive content policy for their local stylesheet, logo and chapter filter; the workbench policy is unchanged. No upload endpoint is introduced.

Source and offline release archives include the manuals. Archive parts use content-derived filenames so a later publication does not reuse immutable cached bytes. The offline manifest is fetched fresh; its part hashes are still verified before assembling a download.

For a new edition, update HTML and print PDFs together, preserve fixture provenance and licenses, verify all relative links and chapter navigation, and review the rendered PDF pages and mobile reading layout. Keep new features and limitations integrated into the relevant teaching chapters.

Publication checks: 23 relevant Node tests; all 167 PDF pages checked for text bounds; relative HTML/PDF links resolved; practice files checked against their manifest. The approved teaching chapters and reference solutions were preserved; only edition/publication framing changed. Browser checks cover desktop and a 390 px viewport, not a new physical-device acceptance run.
