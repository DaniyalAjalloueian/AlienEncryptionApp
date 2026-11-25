# 🛸 Alien Encryption

Encrypt text, files and whole folders with strong, standard cryptography, and optionally turn the result into **alien glyphs**. Exchange a secret key with someone else with no server at all — even with post-quantum protection.

Everything runs locally in your browser. Nothing is uploaded anywhere, except the one-time library loads noted below.

| Edition | File | Encrypts |
|---|---|---|
| Web | `index.html` | Text, any file type, whole folders |
| Desktop (Qt) | `alien_encryption_qt.py` | Text and any file |
| Desktop (Tkinter) | `alien_encryption.py` | Text |

> The web edition has grown well past the desktop editions (file and folder encryption, key exchange, QR codes). Treat the table above as a starting point and update the desktop rows once those files catch up or are retired.

Text messages made in the web and desktop editions are compatible with each other.

<!-- Add screenshots here: docs/web.png, docs/desktop.png -->

## Features

- **Three tabs**
  - **Passphrase:** AES-256-GCM, with the key derived from your passphrase (PBKDF2-HMAC-SHA256, 600,000 rounds) or a 64-character hex key used directly.
  - **Key pair:** RSA-2048 with a random AES key per message, so message length is not limited. Share the public key, keep the private key.
  - **Key exchange:** agree on a shared secret with someone else with no server — see below.
- **Key exchange, no server:** ECDH (P-256), with an optional **post-quantum hybrid** mode (ECDH + ML-KEM-768) so the secret stays safe even if one of the two algorithms is ever broken. You and the other person swap two short codes through any channel you like (chat, email, a phone call) and both end up with the same secret, confirmed by a short check code you read aloud to each other. The codes can be shown as **QR codes** — scan with a camera or load from an image file, so it works between a laptop and a phone. The exchange can run fully offline if the small helper libraries are hosted alongside the page (see Offline use).
- **Alien script:** show encrypted text or codes as glyphs instead of Base64. Decrypting (and key exchange) detects the format automatically, or you can toggle it.
- **Any file type, including folders:** images, video, audio, documents, archives, or a whole folder packed into one encrypted archive. `photo.png` becomes `photo.png.enc` (or `photo.png.enc.alien` with glyphs on); a folder named `Trip` becomes `Trip.enc`. Decrypting restores the original name, and a folder comes back as `Trip.zip`. Originals are never modified or deleted.
- **Large files:** processed in 16 MiB chunks up to 4 GB per file (folders up to 500 MB, since they're assembled in memory first), so big videos don't need to fit in memory all at once. Wrong keys, edits and truncated files are all detected.
- **Optional compression:** compress before encrypting, off by default. Helps documents, text and code; does little for photos, video or anything already compressed.
- **Smart encrypt/decrypt:** the Encrypt or Decrypt button is highlighted automatically based on what's in the box or file list — pasting ciphertext or adding a `.enc`/`.enc.alien` file highlights Decrypt.
- **Auto-save:** optionally download each file the moment it finishes, instead of pressing Save per file.
- **Key tools:** random key generator, public key fingerprint, `.pem` import and export.
- **Locked master key:** optionally save a key in this browser, protected by its own vault password (PBKDF2 600,000 rounds + AES-256-GCM) rather than stored in the clear.
- **Privacy helpers:** Wipe button (with a confirmation prompt), Forget master key (also confirmed), and optional auto-clear after 5 minutes idle.
- **Responsive UI:** works from phone to desktop, in portrait or landscape, with dark and light themes.
- **Convenience:** copy after encrypting, drag and drop (anywhere on the page), Ctrl+Enter to encrypt, Ctrl+Shift+Enter to decrypt.

## Quick start

### Web

Open `index.html` in any modern browser. No install, no server, no account. Browsers only enable the crypto API on `https`, `localhost` or `file://` pages.

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

### Encrypt files and folders

Drop files or a folder onto the **Files** area (or anywhere on the page), or use **Add files** / **Add folder**. The active key is used: your passphrase in Passphrase mode, or your public key in Key pair mode. A file or folder ending in `.enc` or `.enc.alien` highlights **Decrypt** automatically. Turn on **Compress first** or **Auto-save** as needed, and choose **Alien glyphs** or **Binary** as the output format.

### Key exchange, no server

Use this when you and someone else want to agree on a shared secret without a server or existing shared key.

1. One of you presses **Make offer** and sends the code to the other person (copy/paste, QR code, any channel).
2. The other person pastes or scans it, presses **Make reply**, and sends the reply back.
3. The first person pastes or scans the reply and presses **Finish**.
4. Both sides now see the same **check code** — read it aloud to each other. If it doesn't match, something tampered with the exchange; start over.
5. Press **Use as my key** to load the shared secret into Passphrase mode.

Turn on the **post-quantum hybrid** option before starting if you want protection against future quantum computers, not just today's computers.

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
| Key exchange | ECDH (P-256), optionally combined with ML-KEM-768 (post-quantum) |
| Master key vault | PBKDF2-HMAC-SHA256 (600,000 iterations) + AES-256-GCM, separate password from your encryption key |
| Randomness | Operating system CSPRNG |

Please keep in mind:

- **Alien script is an encoding, not encryption.** The security comes from AES, RSA and ECDH/ML-KEM.
- **A passphrase is only as strong as you make it.** Use a long one, or a random hex key.
- **Lose the key, lose the data.** There is no recovery — including for a locked master key if you forget its vault password.
- **The master key, once locked, is still only as safe as your vault password and this browser.** Don't rely on it on a shared or compromised computer.
- **Key exchange depends on the check code actually being compared.** Skipping that step allows a tampered exchange to go unnoticed.
- **The post-quantum and QR-scanning features can load small libraries from a CDN** unless you host them alongside the page yourself (see below). Those loads go to the library host, never your keys or messages.
- **Clipboard history and cloud sync** on your system may keep copies of what you copy.
- This project has **not had an independent security audit**. For high-stakes secrets, use an established, audited tool.

## Offline use

The key-exchange and QR features use small helper libraries. By default they load from a CDN the first time you use them; to run with no network access at all, save these files next to `index.html`:

| File | Source |
|---|---|
| `ml-kem.js` | `https://esm.sh/@noble/post-quantum@0.2.1/ml-kem?bundle` |
| `qrcode.js` | `https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.js` |
| `jsQR.js` | `https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js` |

Note: `ml-kem.js` won't load when the page is opened directly as a `file://` URL in most browsers — host it (even just `python3 -m http.server`) or open it via `localhost`. QR scanning via camera also needs `https` or `localhost`; **Choose image** works everywhere.

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

### Small files (legacy, under the old size limits)

```
"ALF1" | mode | [RSA-wrapped key, key pair mode only] | [salt, passphrase mode only] | nonce 12 | AES-GCM ciphertext + tag
```

### Large files and folders (`.enc` / `.enc.alien`)

```
"ALF2" | mode | [salt 16 | RSA-wrapped key] | compressed flag | chunks
```

- `mode`: 0 = hex key, 1 = key pair, 2 = passphrase.
- The first chunk holds the original filename; folders are packed into a ZIP first, so the stored "filename" is `<folder>.zip`.
- Each chunk is up to 16 MiB, encrypted with AES-GCM; the chunk index and a "last chunk" flag are authenticated with every chunk, so reordering, tampering and truncation all fail to decrypt.
- In alien mode, the whole encrypted file is glyph-encoded, which roughly triples its size — kept under a size limit for that reason.

### Key exchange codes

```
"offer":  0xA1 (classic) or 0xA2 (hybrid) | ECDH public key 65 | [ML-KEM public key, hybrid only]
"reply":  0xB1 (classic) or 0xB2 (hybrid) | ECDH public key 65 | [ML-KEM ciphertext, hybrid only]
```

- The shared secret and check code are both derived with HKDF-SHA256 from the ECDH result (and the ML-KEM shared secret, in hybrid mode), bound to the full offer and reply so neither side can swap in a different exchange after the fact.

</details>

## Project layout

```
index.html                 web edition (single self-contained file)
ml-kem.js                  optional, for fully offline post-quantum key exchange
qrcode.js, jsQR.js         optional, for fully offline QR codes
alien_encryption_qt.py     desktop edition, Qt via qtpy, text and files
alien_encryption.py        desktop edition, Tkinter, text only
```

## Compatibility notes

- Passphrase messages made by the very first web version kept their salt in browser storage and only open in the browser that made them. Messages made by the current versions don't have this limit.
- `.enc` and `.enc.alien` files made by the web edition are not yet supported by the Qt or Tkinter editions.
- A master key saved and locked in the current version is stored differently from the old unencrypted master key; the page offers to re-lock an old one automatically.

## Contributing

Issues and pull requests are welcome. If you find a security problem, please report it privately instead of opening a public issue.

## License

Add your license here (for example MIT) and include a `LICENSE` file.
