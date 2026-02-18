## CryptoShield

Desktop tool for encrypting, decrypting, and verifying the integrity of files using modern cryptography.  
CryptoShield ships with a polished Tkinter GUI (Catppuccin “rice” theme) and a power‑user CLI.

---

### Features

#### Encryption Engines

- **AES-256-GCM** — Password-based authenticated encryption with **streaming I/O**. Recommended for large files.
- **ChaCha20-Poly1305** — AEAD encryption (non-streaming; loads full file into memory).
- **RSA Hybrid** — RSA-4096 for the session key, AES-256-GCM for bulk data. Key-based; no password required.

#### GUI Application

- **Batch encrypt/decrypt** — Files and folder archives (`.csh`)
- **Folder Archive** — Encrypt entire folders into a single `.csh` archive (AES or ChaCha only)
- **Password strength meter** and secure **password generator** (real password copied to clipboard)
- Optional **secure delete** of originals after encryption
- **File preview** for text/images before encrypting
- **SHA-256 hash** generation and **tamper detection** against stored metadata
- **History window** with search and export to CSV/Excel
- **Folder watcher** — Auto-encrypt new files in a watched directory
- **RSA key generation** — 4096-bit keypair saved to `data/keys/`
- **Theme toggle** (Catppuccin Mocha / Latte) and desktop notifications

#### CLI

- `encrypt`, `decrypt`, `hash`, and `verify` commands
- Supports AES-256 and ChaCha20 (RSA is GUI-only)

> **Note**: This is coursework / educational code, not a professionally audited security product. Do not rely on it as the only layer of protection for sensitive data.

---

### Project Structure

| Path | Description |
|------|-------------|
| `src/main.py` | Entry point — GUI by default, CLI with `--cli` |
| `src/gui/app.py` | Tkinter GUI and theming |
| `src/cli.py` | Command-line interface |
| `src/encryption/` | AES, ChaCha20, RSA engines and algorithm registry |
| `src/core/` | File manager, key generation, secure delete, folder watcher |
| `src/integrity/` | SHA-256 hashing and integrity helpers |
| `data/metadata.json` | Encryption history / metadata |
| `data/keys/` | RSA keypair (`public_key.pem`, `private_key.pem`) — created when you generate keys |
| `logs/` | Application log file (`cryptoshield.log`) — created at first run |

---

### Requirements

- **Python 3.10+**
- **Tkinter** (usually bundled with Python)
- Packages: `cryptography`, `Pillow`, `plyer`, `openpyxl`, `watchdog` — install via `pip install -r requirements.txt`

---

### Installation

From the project root:

```bash
python -m venv .venv
.venv\Scripts\activate   # Windows
pip install -r requirements.txt
```

On macOS/Linux:

```bash
source .venv/bin/activate
```

---

### Running the GUI

```bash
python src/main.py
```

#### Typical Workflow

**Step 1 — File Selection**

- **Browse File** or **Add Folder** to select files
- **Preview** text or image files before encrypting

**Step 2 — Security Setup**

- Enter a password or click **Generate Password** (password copied to clipboard)
- Choose **algorithm**: AES-256, ChaCha20, or RSA
- For **RSA**: click **Generate RSA Keys** first (keys saved to `data/keys/`)
- Optionally enable **Secure delete original**

**Step 3 — Actions**

- **Encrypt** / **Decrypt** — Uses password (AES/ChaCha) or RSA keys
- **Folder Archive** — Encrypt a whole folder to `.csh` (AES/ChaCha only)
- **Verify Hash** — Generate SHA-256 hash (copied to clipboard)
- **Check Tamper** — Compare file against stored metadata

**Step 4 — Utilities**

- **History** — View past operations, export to CSV/Excel
- **Watch Folder** — Auto-encrypt new files (requires `watchdog`)
- **Toggle Theme** — Switch dark/light

---

### RSA Workflow

1. Select algorithm **RSA**
2. Click **Generate RSA Keys**
3. Keys are saved to `data/keys/public_key.pem` and `data/keys/private_key.pem`
4. **Encrypt** — Uses public key (no password)
5. **Decrypt** — Uses private key (no password)

*Keys are resolved relative to the current working directory. Run from the project root for expected paths.*

---

### Using the CLI

Direct invocation (from project root):

```bash
python src/cli.py encrypt path/to/file -p "password" --algo AES-256 --secure-delete
python src/cli.py decrypt path/to/file.enc -p "password" --algo AES-256
python src/cli.py hash path/to/file
python src/cli.py verify path/to/file <expected_sha256_hash>
```

Via `main.py`:

```bash
python src/main.py --cli encrypt path/to/file -p "password" --algo ChaCha20
```

CLI algorithms: `AES-256`, `ChaCha20` (RSA is GUI-only).

---

### Streaming vs Non-Streaming

| Engine | Mode | Large Files |
|--------|------|-------------|
| AES-256-GCM | Streaming (64KB chunks) | Yes |
| ChaCha20-Poly1305 | Single-shot (full file in memory) | Limited by RAM |
| RSA Hybrid | Streaming (AES-GCM for data) | Yes |

For very large files, prefer **AES-256** or **RSA**.

---

### Known Limitations

- **RSA** — GUI only; not supported in CLI. Folder archive mode uses AES/ChaCha only.
- **ChaCha20** — Loads entire file into memory; avoid for very large files.
- **RSA key paths** — Keys are looked up in `data/keys/` relative to the current working directory; run from project root for correct behavior.
- **Folder watcher** — Requires optional `watchdog` package.
- **History export** — Excel export requires `openpyxl`.

---

### Tests

If a `tests/` directory exists and you have `pytest` installed:

```bash
pytest tests
```

---

### Cryptographic Design Rationale

- **AES-256-GCM** is used for authenticated symmetric encryption: it provides both confidentiality and integrity (via the GCM authentication tag) and is widely adopted in standards such as TLS 1.3.
- **ChaCha20-Poly1305** serves as an alternative AEAD cipher, offering similar security properties and strong performance on platforms without AES-NI hardware acceleration.
- **RSA-4096** is used only for protecting the session key in hybrid mode, not for encrypting bulk data; this keeps asymmetric overhead minimal.
- **Hybrid encryption** (RSA + AES) mirrors modern systems such as TLS and PGP: a symmetric key is exchanged or wrapped with asymmetric crypto, then bulk data is encrypted symmetrically.
- **Streaming encryption** (AES-GCM, RSA hybrid) processes data in chunks, enabling large-file support without loading the entire file into memory.

---

### Security Notes

- Passwords are **never stored** in metadata.
- Generated passwords are copied to clipboard and cleared after 10 seconds.
- Secure delete attempts to overwrite originals; behavior may vary by OS.
- Keep backups of critical data.

---

### License

All rights reserved unless a license file is provided.
