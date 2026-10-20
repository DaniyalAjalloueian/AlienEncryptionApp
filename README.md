# 🛸 Alien Encryption

Encrypt text and files with strong, standard cryptography, and optionally turn the result into **alien glyphs**.

Everything runs locally on your device. Nothing is uploaded or sent anywhere.

| Edition | File | Encrypts |
|---|---|---|
| Web | `AlienEncryption.html` | Text |
| Desktop (Qt) | `alien_encryption_qt.py` | Text and any file |
| Desktop (Tkinter) | `alien_encryption.py` | Text |

Text messages made in the web and desktop editions are compatible with each other.

<!-- Add screenshots here: docs/web.png, docs/desktop.png -->

## Features

- **Two modes**
  - **Passphrase:** AES-256-GCM, with the key derived from your passphrase (or a 64-character hex key used directly).
  - **Key pair:** RSA-2048 with a random AES key per message, so message length is not limited. Share the public key, keep the private key.
- **Alien script:** show encrypted text as glyphs instead of Base64. Decrypting detects either format automatically.
- **Any file type** (Qt edition): images, video, audio, documents, archives. `photo.png` becomes `photo.png.encrypted`, and decrypting restores the original name. Originals are never modified or deleted.
- **Large files:** processed in 1 MiB pieces, so big videos don't need to fit in memory. Wrong keys, edits and truncated files are detected.
- **Key tools:** random key generator, public key fingerprint, `.pem` import and export, optional saved master key.
- **Privacy helpers:** Wipe button and optional auto-clear after 5 minutes idle.
- **Responsive UI:** the web page works from phone to desktop with dark and light themes; the Qt app stacks its panes when the window is narrow.
- **Convenience:** copy after encrypting, drag and drop, Ctrl+Enter to encrypt, Ctrl+Shift+Enter to decrypt.

## Quick start

### Web

Open `AlienEncryption.html` in any modern browser. No install, no server, no network access. Browsers only enable the crypto API on `https`, `localhost` or `file://` pages.

### Desktop (Qt, recommended)

```bash
pip install cryptography qtpy PySide6
python alien_encryption_qt.py
```

PyQt5 or PyQt6 also work in place of PySide6.

### Desktop (Tkinter)

```bash
pip install cryptography
python alien_encryption.py
```

## Usage

### Encrypt text

1. Choose **Passphrase** or **Key pair**.
2. Enter a passphrase (or press **Random key**), or for key pair mode paste the recipient's public key.
3. Type or paste your message and press **Encrypt**.
4. Copy the result and send it however you like.

To decrypt, paste the message, enter the same passphrase (or your private key) and press **Decrypt**.

### Encrypt files (Qt edition)

Drop files onto the **Files** area, or use **Encrypt files…** and **Decrypt files…**. The active key is used: your passphrase in Passphrase mode, or your public key in Key pair mode. Files ending in `.encrypted` are decrypted when dropped.

### Key pairs

1. Press **Generate key pair**.
2. Send your **public key** to people who want to write to you. Compare the **fingerprint** with them to confirm the key is genuine.
3. Keep the **private key** secret. Use **Save keys** to back it up.

## Security

| Part | Choice |
|---|---|
| Message and file encryption | AES-256-GCM (authenticated) |
| Passphrase to key | PBKDF2-HMAC-SHA256, 600,000 iterations, random 16-byte salt per message |
| Key pair mode | RSA-2048 with OAEP (SHA-256) wrapping a random 256-bit key |
| Randomness | Operating system CSPRNG |

Please keep in mind:

- **Alien script is an encoding, not encryption.** The security comes from AES and RSA.
- **A passphrase is only as strong as you make it.** Use a long one, or a random hex key.
- **Lose the key, lose the data.** There is no recovery.
- **The master key feature stores your key unencrypted** (browser storage on the web, `~/.alien_encryption.json` on desktop). Don't use it on shared computers.
- **Clipboard history and cloud sync** on your system may keep copies of what you copy.
- This project has **not had an independent security audit**. For high-stakes secrets, use an established, audited tool.

## Formats

<details>
<summary>Technical details</summary>

### Text messages

```
[flags 1 byte][salt 16 bytes, only if flags & 2][nonce 12 bytes][AES-GCM ciphertext + tag]
```

- `flags & 2`: the key came from a passphrase and the salt is stored in the message.
- Key pair messages are JSON `{"k": <RSA-wrapped key>, "d": <message above>}`.
- The bytes are Base64-encoded. In alien mode that Base64 text is mapped through a 256-glyph alphabet with separators, and decoding ignores the separators.

### Files (`.encrypted`)

```
"ALIENENC" | version 1 | mode | [salt 16 | wrapped key] | nonce prefix 8 | chunks
```

- `mode`: 0 = hex key, 1 = passphrase, 2 = key pair.
- Each chunk is up to 1 MiB of data, encrypted with AES-GCM using nonce = prefix + 32-bit counter.
- The header and a "last chunk" flag are authenticated with every chunk, so tampering and truncation fail to decrypt.

</details>

## Project layout

```
AlienEncryption.html      web edition (single self-contained file)
alien_encryption_qt.py    desktop edition, Qt via qtpy, text and files
alien_encryption.py       desktop edition, Tkinter, text only
```

## Compatibility notes

- Passphrase messages made by the very first web version kept their salt in browser storage and only open in the browser that made them. Messages made by the current versions don't have this limit.
- `.encrypted` files can only be opened with the Qt edition.

## Contributing

Issues and pull requests are welcome. If you find a security problem, please report it privately instead of opening a public issue.

## License

Add your license here (for example MIT) and include a `LICENSE` file.
