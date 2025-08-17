# secutor

Interactive terminal UI for managing a private PKI: root and intermediate CAs, server and client certificates, PKCS#12 profiles, full chain export, revocation with CRLs, plus re-linking and re-signing certs against a different CA. Everything lives in encrypted local SQLite "contexts" — no external services, no daemons.

[![npm](https://img.shields.io/npm/v/secutor.svg)](https://www.npmjs.com/package/secutor)

## Highlights

- **Multi-level PKI** — issue a root CA, then intermediate CAs under it, then server/client leaves under any CA. Chains of arbitrary depth are walked and verified.
- **Chain validation** — every certificate is checked against its issuer and ancestors; SAN/SNI, validity windows, expiry and revocation are surfaced with a clear ✔/✘ status.
- **Revocation + CRL** — revoke any non-root certificate (intermediate or leaf). Revoked ancestors cascade: descendants stop verifying. Export a signed v2 X.509 CRL straight from a CA's details screen.
- **Re-link & re-sign** — recover from broken chains. *Attach* (DB-only) re-points a cert at a CA in the DB without touching the cert PEM, useful after a CA was deleted and re-imported. *Re-sign* generates a fresh signature with another CA: same public key, same subject and SANs, new issuer + new serial — the leaf's existing private key keeps working.
- **Full chain export** — for any CA, export `cert + parents up to root`, the entire signed *subtree* (CA + every descendant), or a CRL. Standard PEM bundle / cert-only / key-only / chain are also available for leaves.
- **PKCS#12 profiles** — bundle leaf + key + chain into a password-protected `.p12` for browsers, mobile, or service deployment. Import and decrypt existing `.p12` files too.
- **Encrypted contexts** — a *context* is one independent PKI. Each context is a single SQLite file, optionally encrypted at rest with a password (AES-GCM). Switch between contexts inside the app or import/export them as portable files.
- **Import existing material** — drop in PEM (`.crt`/`.pem`/`.cer`/combined) or PKCS#12 (`.p12`/`.pfx`); the importer detects and stores intermediates/roots as CAs and links the chain.
- **i18n** — built-in English and Russian (toggle in Settings).
- **Mouse + keyboard** — wheel scroll, click selection, function keys, full keyboard navigation.

## Install

```bash
npm install -g secutor
```

Then run:

```bash
secutor
```

CLI flags: `secutor --help`.

## Requirements

- **Node.js 18.17+** (Node 20 LTS or 22 LTS recommended).
- macOS, Linux, or Windows 10+.

## Where data is stored

- macOS / Linux: `~/.secutor/`
- Windows: `%USERPROFILE%\.secutor\`

Override with the `SECUTOR_HOME` environment variable.

Layout:

```
~/.secutor/
├── meta.json                  # context registry
├── locale.json                # UI language
└── contexts/
    └── <name>/
        ├── context.json       # context metadata
        ├── store.db           # plaintext SQLite (if not encrypted)
        └── store.enc          # AES-GCM ciphertext (if encrypted)
```

Encrypted contexts are decrypted to a temp file (mode 0600) for the duration of the session and re-encrypted on every write.

## Quick tour

1. **First run** — pick or create a context. Optionally encrypt it with a password.
2. **Create CA** — generates a self-signed root CA (RSA-2048, SHA-256).
3. **Issue intermediate CA** — pick a parent CA, fill in the subject; gets `basicConstraints cA:true`, optional `pathLenConstraint`, AKI/SKI extensions.
4. **Issue server / client cert** — pick the issuing CA, fill in CN, SANs (server only), validity. Signed by the chosen CA, AKI links to it.
5. **Profiles (P12)** — bundle a leaf + private key + full CA chain into a PKCS#12 file with a password.
6. **Verify** — pick a cert (and optional SNI hostname); the app walks the chain via DB metadata, runs `node-forge`'s chain verification, checks expiry, SNI matching, and revocation status of every ancestor.
7. **Revoke** — open a certificate's details and press `R`. Confirm. Verification fails immediately for that cert and any descendant. Press `R` again to clear.
8. **Manage issuer** — on cert details, press `M`. Two modes:
   - *Attach to existing CA* — DB metadata only. Useful if you deleted a CA and re-imported it (the new row has a different `id`, so the orphaned children show "Missing issuer"). The picker flags CAs whose subject matches the cert's `Issuer` field; picking a non-matching one is allowed but warns that cryptographic verification will still fail.
   - *Re-sign with a different CA* — generates a brand-new signature using the chosen CA's private key. The leaf's public key, subject, SANs, validity, and extensions are preserved; issuer DN, AKI, and serial are updated. Existing private keys stay valid because they pair with the public key, not the cert. Only CAs that have a private key in the DB are eligible.
9. **Export** — from any cert's details, press `E`. Options:
   - `cert` (PEM) — just the certificate
   - `key` (PEM) — just the private key
   - `bundle` — cert + key concatenated
   - `chain` — cert + parent CAs up to root
   - `subtree` *(CA only)* — this CA + every cert it has signed, transitively
   - `CRL` *(CA only)* — signed v2 X.509 CRL listing this CA's directly-revoked children

## Keyboard

| Key | Action |
| --- | --- |
| `↑` `↓` / Tab | Navigate items / fields |
| `Enter` | Open / submit |
| `Esc` | Back / cancel |
| `E` | Export (on cert details) |
| `P` | Make P12 profile (on cert details) |
| `V` | Verify (on cert details) |
| `M` | Manage issuer — attach to a CA or re-sign with a different one (on cert details) |
| `R` | Revoke / Unrevoke (on cert details, non-root) |
| `D` | Delete (on lists) |
| `F10` | Quit |

## Windows install troubleshooting

`secutor` depends on [`better-sqlite3`](https://github.com/WiseLibs/better-sqlite3), a native module. On Windows the install can fail in a few specific ways:

### 1. "No prebuilt binaries found" / `node-gyp rebuild` errors

`better-sqlite3` ships prebuilt binaries for the **current LTS and active Node versions**. If you're on a brand-new or non-LTS Node release, no prebuild exists and npm tries to compile from source.

**Fix:** use a supported Node version. The most reliable on Windows are **Node 20 LTS** or **Node 22 LTS**. With [`nvm-windows`](https://github.com/coreybutler/nvm-windows):

```powershell
nvm install 22
nvm use 22
npm install -g secutor
```

### 2. Compilation fallback fails (Python / MSBuild missing)

If a prebuild really isn't available for your platform (e.g. unusual ARM64 Windows + bleeding-edge Node), npm will fall back to compiling. That needs:

- Python 3.x on `PATH`
- Visual Studio 2022 Build Tools with the **"Desktop development with C++"** workload

Install the toolchain in one shot via the Microsoft installer:

```powershell
npm install --global --production windows-build-tools
```

Then retry `npm install -g secutor`.

### 3. Behind a corporate proxy / firewall

`better-sqlite3` fetches prebuilds from GitHub Releases via `prebuild-install`. If GitHub is blocked, prebuild download fails silently and npm falls into the compile path. Either:

- Configure npm to use your proxy: `npm config set proxy http://proxy:port` and `npm config set https-proxy http://proxy:port`, **or**
- Allowlist `github.com` and `objects.githubusercontent.com`, **or**
- Install the build toolchain (above) and let it compile locally.

### 4. EACCES / permission errors during global install

On Windows, the npm global prefix is `%APPDATA%\npm` and shouldn't need admin. If you've reconfigured it to a system path, run the install from an **elevated PowerShell** or use [`fnm`](https://github.com/Schniz/fnm) / `nvm-windows` so the prefix stays per-user.

### 5. Display issues (mouse / box-drawing / emoji)

`secutor` uses the SGR mouse protocol and Unicode box-drawing characters. Use **Windows Terminal** (default on Windows 11). Legacy `cmd.exe` and old `conhost` will render glitches but still function.

### Verify the install

```powershell
secutor --help
```

If that prints the help text, the binary loaded successfully and `better-sqlite3` linked correctly.

## Development

```bash
git clone <repo>
cd certificate-manager
npm install
npm run dev          # runs from TypeScript via tsx
npm run build        # emits dist/
node dist/cli.js     # run the build
```

Project layout:

```
src/
├── cli.tsx                # entrypoint, raw stdin / mouse setup
├── app.tsx                # router
├── certs/
│   ├── generator.ts       # createCA, issueIntermediateCA, issueCert, resignCertificate, buildP12, buildCRL, collectSubtreePems
│   ├── importer.ts        # PEM / PKCS#12 import
│   ├── parser.ts          # cert field extraction
│   └── verify.ts          # chain + revocation + SNI verification
├── components/            # ink components (Menu, Form, FileExplorer, ...)
├── i18n/locales/          # en.ts, ru.ts
├── input/                 # mouse + F-key proxy
├── screens/               # one file per screen
├── state/                 # AppContext (router stack, toasts)
└── storage/
    ├── db.ts              # SQLite open/close, encryption, migrations
    ├── crypto.ts          # AES-GCM context encryption
    ├── repos.ts           # cert + profile CRUD
    └── paths.ts           # ~/.secutor layout
```

## Security notes

- Keys are RSA-2048, signatures SHA-256.
- Self-signed roots cannot be revoked (no issuer to revoke against). Intermediates and leaves can.
- The encrypted-context password derives an AES-256-GCM key; a wrong password fails decryption rather than yielding garbage.
- Storage files are written with mode `0600` on POSIX. Windows ignores POSIX modes; rely on user-profile ACLs.
- This is a local PKI tool. It does **not** publish OCSP responders or distribute CRLs over HTTP — you have to ship the exported `.crl` to relying parties yourself.
- *Attach to existing CA* is a DB-only relink — it does **not** validate that the picked CA actually signed the certificate. It's a recovery aid; verification (`V`) still runs the cryptographic check and will reject an incorrect attachment.
- *Re-sign* changes the cert's signature, issuer, AKI and serial. Anyone holding a copy of the **old** cert (or a CRL that listed it) won't recognize the new one — distribute the re-signed cert to relying parties.

## License

MIT
