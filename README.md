## CryptoShield

Desktop tool for encrypting, decrypting and verifying the integrity of files using modern cryptography.  
CryptoShield ships with a polished Tkinter GUI (Catppuccin “rice” theme) and a power‑user CLI.

---

### Features

- **Multiple algorithms**
  - **AES‑256‑GCM**
  - **ChaCha20‑Poly1305**
  - **RSA hybrid mode** (RSA for keys, AES for bulk data)
- **GUI application**
  - Batch **encrypt/decrypt** files and folders
  - **Password strength meter** and secure **password generator**
  - Optional **secure delete** of originals after encryption
  - File **preview** for text/images before encrypting
  - **SHA‑256 hash** generation and **tamper detection** against stored metadata
  - **History window** with search and export to **CSV / Excel**
  - Optional **folder watcher** that auto‑encrypts new files
  - Light/dark **theme toggle** and desktop notifications
- **CLI for advanced users**
  - `encrypt`, `decrypt`, `hash`, and `verify` commands

> **Note**: This is coursework / educational code, not a professionally audited security product. Do not rely on it as your only layer of protection for highly sensitive data.

---

### Project structure

- **`src/main.py`**: Entry point that launches the GUI by default, or the CLI when called with `--cli`.
- **`src/gui/app.py`**: Tkinter GUI (`CryptoShieldApp`) and theming.
- **`src/cli.py`**: Command‑line interface.
- **`src/encryption/`**: AES, ChaCha20, RSA engines and algorithm registry.
- **`src/core/`**: File manager, key generation, secure delete, folder watcher.
- **`src/integrity/`**: Hashing and integrity helpers.
- **`data/metadata.json`**: Stores encryption history / metadata.
- **`tests/`**: Basic tests for encryption and integrity.

---

### Requirements

- **Python 3.10+** (recommended)
- OS: developed and tested on **Windows**, should work on other platforms that support Tkinter.
- Python packages (install via `requirements.txt`):
  - `cryptography`
  - `Pillow`
  - `plyer`
  - `openpyxl`
  - `watchdog`

---

### Installation

From the project root:

```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

On macOS / Linux, activate the virtualenv with:

```bash
source .venv/bin/activate
```

---

### Running the GUI

From the project root:

```bash
python src/main.py
```

This opens the CryptoShield desktop window.

**Typical GUI workflow**

- **Select files/folder**
  - Click **“Browse File”** or **“Add Folder”**.
  - Optionally **Preview** a file before encrypting.
- **Set security**
  - Enter a password or click **“Generate”** for a random strong password.
  - Watch the **strength indicator**; aim for “strong”.
  - Choose an **algorithm** (AES‑256, ChaCha20, or RSA).
  - Optionally toggle **“Secure delete original”**.
- **Run actions**
  - Click **Encrypt** or **Decrypt**.
  - Use **Verify Hash** to generate a SHA‑256 hash (copied to clipboard).
  - Use **Check Tamper** to compare an encrypted file against stored metadata.
  - Use **History** to inspect past operations and export them as CSV/Excel.
  - Use **Watch Folder** to auto‑encrypt new files in a chosen directory.

---

### Using the CLI

You can use the CLI directly, or via `main.py` with the `--cli` switch.

**Direct CLI invocation (from project root)**

```bash
python src/cli.py encrypt path/to/file -p "your-password" --algo AES-256 --secure-delete
python src/cli.py decrypt path/to/file.enc -p "your-password" --algo AES-256
python src/cli.py hash path/to/file
python src/cli.py verify path/to/file <expected_sha256_hash>
```

**Via `main.py`**

```bash
python src/main.py --cli encrypt path/to/file -p "your-password" --algo ChaCha20
```

Available algorithms for `--algo` / `--algorithm`:

- `AES-256`
- `ChaCha20`

---

### Tests

If you have `pytest` installed:

```bash
pytest tests
```

This runs basic tests for the encryption engines and integrity utilities.

---

### Security notes

- **Passwords are never stored** in metadata; only file paths, algorithm, sizes and hashes are recorded.
- Clipboard contents holding generated passwords are **cleared after a short timeout** in the GUI.
- Secure delete attempts to overwrite and remove original files, but behaviour can differ by OS and filesystem.
- Always keep **backups** of critical data and do not rely solely on a single tool for security.

---

### License

If this is coursework and no explicit license is provided, the code is effectively **“all rights reserved”** by default.  
Add an explicit license file (e.g. MIT, GPL, or university‑specific terms) if you intend to share or open‑source the project.

