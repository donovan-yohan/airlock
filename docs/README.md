# Airlock documentation site

This directory is a dependency-free static site suitable for GitHub Pages. It contains three intentionally separate deliverables:

- [`architecture.md`](architecture.md) and its raw Mermaid sources describe system boundaries, installation topology, and managed-instruction ownership;
- [`approval-timing.md`](approval-timing.md) and its raw Mermaid source describe approval, manual execution, receipts, and external verification over time;
- [`index.html`](index.html) is the marketing landing page, with additional HTML documentation pages sharing [`assets/styles.css`](assets/styles.css).

## Render diagrams

The HTML site uses checked-in SVGs rather than client-side Mermaid. Re-render all Mermaid sources with the pinned CLI version:

```sh
./docs/diagrams/render.sh
```

`tests/test_docs.py` verifies that every raw source has one rendered SVG carrying the current source digest and that Markdown Mermaid blocks remain byte-for-byte aligned with the raw `.mmd` files.

## Preview locally

From the repository root:

```sh
python3 -m http.server 4173 --bind 127.0.0.1 --directory docs
```

Then open <http://127.0.0.1:4173/>.

## Publish with GitHub Pages

After the repository has a GitHub remote, configure Pages to **Deploy from a branch** using branch `main` and folder `/docs`. The checked-in `.nojekyll` file keeps the site on the plain static-file path; no Jekyll theme, package install, or client-side JavaScript is required.
