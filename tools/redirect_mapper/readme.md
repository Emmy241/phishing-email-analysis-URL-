# redirect_mapper.py

A defensive URL analysis utility that maps redirect chains end-to-end — including HTTP redirects (301/302/307/308) and browser-level redirects (JavaScript + meta refresh) via Playwright.

Useful for phishing investigations where a "trusted-looking" URL (cloud storage, CDN, shortener) ultimately leads elsewhere.

> **Safety:** No form submission, no clicking, no file downloads — navigate and record only.

---

## Setup

```bash
python3 -m venv venv
source venv/bin/activate          # Windows: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
playwright install
```

---

## Usage

**HTTP redirects only**
```bash
python redirect_mapper.py "hxxps[://]example[.]com"
```

**Browser mode + evidence capture**
```bash
python redirect_mapper.py "hxxps[://]storage[.]googleapis[.]com/path/page[.]html" \
  --browser \
  --json-out evidence/redirects.json --pretty \
  --screenshot-out evidence/final.png \
  --har-out evidence/chain.har
```

**Batch mode (one URL per line in a `.txt` file)**
```bash
python redirect_mapper.py urls.txt --browser --json-out out/all.json --pretty
```

Accepts **defanged** input (e.g. `hxxps[://]example[.]com`).

---

## Key Flags

| Flag | Description |
|---|---|
| `--browser` | Enable Playwright to catch JS/meta refresh redirects |
| `--json-out <file>` | Save results as JSON |
| `--screenshot-out <file>` | Save screenshot of final page (browser mode) |
| `--har-out <file>` | Save HAR network log (browser mode) |
| `--pretty` | Pretty-print JSON output |
| `--max-hops <n>` | Max hops to follow (default: 10) |
| `--wait-after-load-ms <ms>` | Extra wait time for delayed JS redirects |
| `--allow-http` | Allow plain `http://` URLs (blocked by default) |
| `--no-tls-verify` | Disable TLS verification (controlled testing only) |
| `--block-third-party` | Block third-party requests to reduce noise |

---

## Output

Terminal prints a hop-by-hop chain with status codes and locations. JSON output includes `httpx_chain`, `browser_chain`, `final_url`, and `notes`.

> **Note:** HAR files may contain identifiers — sanitize before sharing.

---

## License

[MIT](./LICENSE) © 2026 Emmanuel Ajayi

