# secutor

Interactive terminal UI for managing a private PKI plus modern crypto tooling: root and intermediate CAs, server and client certificates with RSA / ECDSA / Ed25519 keys, PKCS#12 profiles, full chain export, revocation with CRLs, file & application signing, and SSH key generation. Exports as a ready-to-use **nginx** server block or **Traefik** (file provider / ACME) bundle, with one-keystroke copy to the system clipboard. CAs can be protected with a passphrase. Everything lives in encrypted local SQLite "contexts" — no external services, no daemons.

[![GitHub](https://img.shields.io/badge/GitHub-KamiGhost1%2Fsecutor-181717?logo=github)](https://github.com/KamiGhost1/secutor) [![npm](https://img.shields.io/npm/v/secutor.svg)](https://www.npmjs.com/package/secutor) 

## Highlights

- **Multi-level PKI** — issue a root CA, then intermediate CAs under it, then server/client leaves under any CA. Chains of arbitrary depth are walked and verified.
- **Modern key algorithms** — RSA 2048 / 3072 / 4096, ECDSA P-256 / P-384, and Ed25519 for X.509. Algorithms can mix freely (e.g. RSA root signing ECDSA leaves) and are validated end-to-end against `openssl verify`.
- **Chain validation** — every certificate is checked against its issuer and ancestors; SAN/SNI, validity windows, expiry and revocation are surfaced with a clear ✔/✘ status.
- **Revocation + CRL** — revoke any non-root certificate (intermediate or leaf). Revoked ancestors cascade: descendants stop verifying. Export a signed v2 X.509 CRL straight from a CA's details screen — RSA and ECDSA/Ed25519 CAs all sign valid CRLs.
- **Re-link & re-sign** — recover from broken chains. *Attach* (DB-only) re-points a cert at a CA in the DB without touching the cert PEM, useful after a CA was deleted and re-imported. *Re-sign* generates a fresh signature with another CA: same public key, same subject and SANs, new issuer + new serial — the leaf's existing private key keeps working.
- **Passphrase-protected CAs** — when you create a CA you may set a passphrase; the private key is stored as encrypted PKCS#8 (AES-256-CBC) and the passphrase is required at every issuance, re-sign, renew or CRL operation.
- **File & application signing** — sign any byte stream (binaries, archives, releases) with a stored certificate's key. Two output modes: a detached `.sig` JSON manifest, or a self-describing bundle that prepends the manifest to the data. Verification supports fingerprint pinning so a swapped cert is rejected.
- **SSH keys** — generate Ed25519, RSA 2048/3072/4096, ECDSA P-256/P-384 SSH identity keys, store them encrypted inside the context, and export to `~/.ssh` in OpenSSH v1 format (the format `ssh-keygen` and `ssh-agent` actually accept).
- **Full chain export** — for any CA, export `cert + parents up to root`, the entire signed *subtree* (CA + every descendant), or a CRL. Standard PEM bundle / cert-only / key-only / chain are also available for leaves.
- **Ready-to-use web-server configs** *(opt-in)* — export any leaf cert as a complete **nginx** server block, a **Traefik** file-provider `dynamic.yml`, or a **Traefik + ACME** (Let's Encrypt) static + dynamic pair. `server_name` / `Host` rules are pre-filled from the cert's CN + SANs (editable), and the bundle writes `cert.crt` / `key.key` / `chain.crt` next to the config file in one selected folder. Hidden by default — enable in **Settings → "Show nginx / Traefik configs in export"** to surface them in the cert-export menu.
- **Clipboard export** — every text export (cert, key, bundle, chain, subtree, CRL as base64, or a full nginx / Traefik bundle) can be sent straight to the system clipboard via `pbcopy` / `xclip` / `xsel` / `wl-copy` / `clip` — no extra dependencies.
- **`/` quick filter** — press `/` on any list (certificates, SSH keys, P12 profiles, contexts) to type-to-filter by name, CN, SANs, fingerprint, or comment. `Esc` clears.
- **PKCS#12 profiles** — bundle leaf + key + chain into a password-protected `.p12` for browsers, mobile, or service deployment. Import and decrypt existing `.p12` files too.
- **Encrypted contexts** — a *context* is one independent PKI. Each context is a single SQLite file, optionally encrypted at rest with a password (AES-GCM). Switch between contexts inside the app or import/export them as portable files.
- **Import existing material** — drop in PEM (`.crt`/`.pem`/`.cer`/combined) or PKCS#12 (`.p12`/`.pfx`); the importer detects and stores intermediates/roots as CAs and links the chain.
- **Key bundles (`.skb`)** — move certs, SSH keys, P12 profiles or whole CA subtrees between contexts (or machines) without losing metadata. Encrypted PKCS#8 keys travel as-is — secutor never has to know their passphrase. Bundles can be wrapped in a scrypt + AES-256-GCM envelope for transport over untrusted channels. Hotkey `T` on any cert / SSH-key / profile.
- **Hubs (remote ACME admin)** — connect over mTLS to a running [`secutor-acme`](acme-server/) hub and drive it from the same TUI: browse certificates, revoke, ban accounts (with cascading revocation), inspect audit + stats dashboards, verify the hub's CA key matches what you expect, rotate the signing intermediate (stage → promote → rollback), kick off a background "re-sign all active leaves" job. Server-managed DNS-01 — the hub publishes TXT records on the client's behalf via configured providers.
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

CLI flags: `secutor --help`. For non-interactive signing and verification (CI / scripting) see [Non-interactive CLI](#non-interactive-cli).

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
├── settings.json              # UI preferences (e.g. show web-server configs in export)
├── hubs.json                  # registered ACME hubs (id, baseUrl, pinned server fp, client-auth handle)
├── hubkeys/                   # standalone client identities used to log into hubs
│   └── <entry>/
│       ├── cert.pem
│       ├── key.pem(.enc)      # plain PKCS#8 or AES-256-GCM wrapped
│       └── meta.json
└── contexts/
    └── <name>/
        ├── context.json       # context metadata
        ├── store.db           # plaintext SQLite (if not encrypted)
        └── store.enc          # AES-GCM ciphertext (if encrypted)
```

Encrypted contexts are decrypted to a temp file (mode 0600) for the duration of the session and re-encrypted on every write.

`hubs.json` and `hubkeys/` are populated only after you add at least one hub via the **Hubs** main-menu entry (see [Hubs](#hubs-remote-acme-admin) below).

## Quick tour

1. **First run** — pick or create a context. Optionally encrypt it with a password.
2. **Create CA** — generates a self-signed root CA. Pick the key algorithm (RSA-2048/3072/4096, ECDSA P-256/P-384, Ed25519). Optionally set a passphrase to encrypt the CA private key at rest.
3. **Issue intermediate CA** — pick a parent CA, fill in the subject and the desired key algorithm; gets `basicConstraints cA:true`, optional `pathLenConstraint`, AKI/SKI extensions. Algorithms can mix freely with the parent.
4. **Issue server / client cert** — pick the issuing CA, fill in CN, SANs (server only), validity, and key algorithm. If the issuing CA's key is password-protected, you'll be prompted for that passphrase. Signed by the chosen CA, AKI links to it.
5. **Profiles (P12)** — bundle a leaf + private key + full CA chain into a PKCS#12 file with a password.
6. **Verify** — pick a cert (and optional SNI hostname); the app walks the chain via DB metadata, runs cryptographic chain verification, checks expiry, SNI matching, and revocation status of every ancestor.
7. **Revoke** — open a certificate's details and press `R`. Confirm. Verification fails immediately for that cert and any descendant. Press `R` again to clear.
8. **Manage issuer** — on cert details, press `M`. Two modes:
   - *Attach to existing CA* — DB metadata only. Useful if you deleted a CA and re-imported it (the new row has a different `id`, so the orphaned children show "Missing issuer"). The picker flags CAs whose subject matches the cert's `Issuer` field; picking a non-matching one is allowed but warns that cryptographic verification will still fail.
   - *Re-sign with a different CA* — generates a brand-new signature using the chosen CA's private key. The leaf's public key, subject, SANs, validity, and extensions are preserved; issuer DN, AKI, and serial are updated. Existing private keys stay valid because they pair with the public key, not the cert. Only CAs that have a private key in the DB are eligible.
9. **Export** — from any cert's details, press `E`. Pick a format, then choose **Save to file/folder** or **Copy to clipboard**. Available formats:
   - `cert` (PEM) — just the certificate
   - `key` (PEM) — just the private key
   - `bundle` — cert + key concatenated
   - `chain` — cert + parent CAs up to root
   - `nginx config + cert files` *(only if enabled in Settings)* — a `server { ... }` block with TLS 1.2/1.3, `server_name`, `ssl_certificate` / `ssl_certificate_key` pointing at the bundled files in your chosen install dir (defaults to `/etc/nginx/certs/<name>`)
   - `Traefik (file provider)` *(only if enabled in Settings)* — a dynamic `<name>.dynamic.yml` with `tls.certificates`, a router and a service stub
   - `Traefik with ACME (Let's Encrypt)` *(only if enabled in Settings)* — `traefik.yml` (entryPoints, HTTP→HTTPS redirect, `certificatesResolvers` with HTTP-01) + `<name>.dynamic.yml` with the cert as a default-store fallback
   - `subtree` *(CA only)* — this CA + every cert it has signed, transitively
   - `CRL` *(CA only)* — signed v2 X.509 CRL listing this CA's directly-revoked children
10. **Sign a file** — pick a leaf cert (server or client) and a file. Choose detached (writes `<file>.sig`) or bundled (a self-describing `.secsig` blob that contains both manifest and data). The manifest pins the signer's certificate by SHA-256 fingerprint.
11. **Verify a signature** — point at the data and the manifest (or the bundle); the app rebuilds the data hash, locates the signer cert, and validates the signature. Wrong cert, tampered data, or a fingerprint-pinning mismatch all surface as a single clear ✘.
12. **SSH keys** — generate an Ed25519/RSA/ECDSA SSH identity key with an optional passphrase. Stored alongside certs in the same context. Export to `~/.ssh/<name>` in OpenSSH v1 format (the format `ssh-keygen`/`ssh-agent` actually accept) with `0600` perms.

## Settings

Open from the contexts screen with `S`. Two options live there today:

- **Language** — toggle between English and Русский. Persisted to `~/.secutor/locale.json`.
- **Show nginx / Traefik configs in export** — when enabled, the cert-export menu lists `nginx`, `Traefik (file provider)`, and `Traefik with ACME` formats. Off by default — flip it on once and they appear in every cert's `E` menu thereafter. Persisted to `~/.secutor/settings.json`.

`Enter` toggles the focused option (and shows a toast); `Esc` returns to the previous screen.

## Non-interactive CLI

`secutor` also exposes the **sign** and **verify** operations as plain
subcommands, so you can drive them from CI pipelines, shell scripts, or
release tooling without ever entering the TUI. All passwords can be passed
on the command line, read from stdin, or — if you are on a TTY — prompted
for interactively.

```bash
secutor sign   <file> [options]
secutor verify <file> [options]
```

Exit codes:

- `0` — success / signature is valid
- `1` — signature is invalid (wrong, mismatched, data tampered, fingerprint pin failed)
- `2` — usage or I/O error (bad flag, missing file, wrong password, context not found)

### `secutor sign <file>`

Produces a signature for `<file>`. Two output modes:

- **detached** (default) — writes a JSON manifest to `<file>.sig` (or to `--out`).
- **bundle** — writes a single self-describing `.secsig` blob to `<file>.secsig` (or to `--out`) that contains both the manifest and the original data.

The signer can come from a stored context or from raw PEM files on disk.

**From a context (uses certificates already in `~/.secutor`):**

```bash
# Password as a flag (visible in process listings — fine for one-shot scripts):
secutor sign release.tar.gz \
    --context prod --cert release-signer \
    --context-password "$CTX_PW"

# Password piped on stdin (preferred for CI — does not leak to argv):
echo "$CTX_PW" | secutor sign release.tar.gz \
    --context prod --cert release-signer \
    --context-password-stdin
```

If the *stored private key* is itself password-protected, pass
`--key-password <pw>` or `--key-password-stdin` in addition to the context
password. (Only one `*-password-stdin` flag can be used per invocation —
stdin is single-use.)

**From files (no context needed — works on any machine):**

```bash
# Plain PEM key:
secutor sign release.tar.gz \
    --key-file ./signer.key \
    --cert-file ./signer.crt          # cert is optional; if given, it's
                                       # embedded in the manifest so the
                                       # verifier needs no separate copy.

# Encrypted PKCS#8 key, password supplied as a flag:
secutor sign release.tar.gz \
    --key-file ./signer.key --cert-file ./signer.crt \
    --key-password 's3cr3t'

# Same, but reading the password from stdin:
echo 's3cr3t' | secutor sign release.tar.gz \
    --key-file ./signer.key --cert-file ./signer.crt \
    --key-password-stdin

# Bundle mode + explicit output path:
secutor sign release.tar.gz \
    --key-file ./signer.key --cert-file ./signer.crt \
    --mode bundle --out release.tar.gz.secsig
```

If neither `--*-password` nor `--*-password-stdin` is supplied for an
encrypted source and you're attached to a TTY, the password is prompted
with characters masked. Without a TTY the command fails with a clear
error instead of hanging.

### `secutor verify <file>`

By default the verifier trusts the certificate baked into the manifest —
that's how the bundle mode works out of the box:

```bash
secutor verify release.tar.gz                # uses release.tar.gz.sig
secutor verify release.tar.gz.secsig         # bundle mode, no --sig needed
secutor verify release.tar.gz --sig path/to/manifest.json   # custom sig path
```

For real release validation you usually want to **pin** the signer
yourself instead of trusting the manifest blindly. Two ways:

**Pin a certificate / public-key PEM file:**

```bash
# Distribute signer.crt next to your release and verify against it:
secutor verify release.tar.gz --signer-file ./signer.crt

# Or pin by SHA-256 fingerprint only (no cert file needed):
secutor verify release.tar.gz \
    --fingerprint 4c9748f5e6a53f9855268a7794472c8650c1a13633d2102c21caef6ceba2c065
```

**Pin a certificate from a stored context:**

```bash
secutor verify release.tar.gz \
    --context prod --cert release-signer \
    --context-password "$CTX_PW"

# Same, with the context password on stdin:
echo "$CTX_PW" | secutor verify release.tar.gz \
    --context prod --cert release-signer \
    --context-password-stdin
```

`--signer-file` and `--context + --cert` cannot be combined. `--fingerprint`
can be combined with any source as an extra pinning check.

### Tip: bootstrap a portable verifier

You can export a signer cert from the TUI (cert details → `E` → "Save to file")
and ship just that `.crt` alongside your signature. The receiver verifies
with `secutor verify file --signer-file signer.crt` and never needs your
context.

### `secutor keys export | import | transfer`

Move secutor's own material (certs, SSH keys, P12 profiles, whole CA
subtrees) between contexts as a single `.skb` (secutor key-bundle) file.
The bundle format is documented at the top of
[`src/transfer/keyBundle.ts`](src/transfer/keyBundle.ts); the short version
is *magic + JSON manifest + payload*, optionally wrapped in a scrypt +
AES-256-GCM envelope.

Encrypted PKCS#8 private keys travel as they are. secutor never has to know
the per-key passphrase to ship them.

```bash
# Export a cert (with its issuer chain) to a plain .skb file.
secutor keys export mysvc --context prod --include-parents \
    --out /tmp/mysvc.skb

# Export the entire subtree rooted at a CA, wrapped in a password envelope.
secutor keys export rootca --context prod --subtree --encrypt \
    --bundle-password "$BUNDLE_PW" --out /tmp/root-subtree.skb

# Same operation but kind=ssh / kind=profile.
secutor keys export deploy --context prod --kind ssh --out deploy.skb

# Import into another context. Encrypted bundles will prompt or accept
# --bundle-password / --bundle-password-stdin.
secutor keys import /tmp/mysvc.skb --context ops

# One-shot context → context transfer (no intermediate file).
secutor keys transfer mysvc --from prod --to ops --include-parents
```

Conflicts on import are surfaced (not hidden): a duplicate fingerprint is
reported as `skipped`, a name collision is suffix-resolved with a `note`,
and an existing row whose `key_pem` was empty gets filled in (or
overwritten with `--overwrite-key`). Imports run inside a SQLite
transaction — any failure rolls back the whole bundle.

Full flag list: `secutor keys --help`.

## Hubs (remote ACME admin)

When you've deployed [`secutor-acme`](acme-server/) somewhere with its
admin API enabled (mTLS-only, separate listener — see
[acme-server/docs/admin-api.md](acme-server/docs/admin-api.md)), the same
TUI can drive it remotely. From the main menu pick **🌐 Hubs**.

**Add a hub** (`A` on the Hubs screen):

1. Type a display name + base URL (`https://acme.lan.vpn:8444`).
2. Pick the client-identity source:
   - **Cert from this context** — picks one of your `client`-type certs.
   - **Cert/key files on disk** — point at `cert.pem` and `key.pem` paths.
   - **Cert from hub keystore** — pick an entry from `~/.secutor/hubkeys/`
     (a standalone, context-free keystore for hub logins).
3. TUI probes the server, shows its SHA-256 fingerprint, asks you to pin it
   (TOFU). After that, every connection verifies the cert fingerprint
   regardless of OS trust stores.

The mTLS client cert is **not** required to share a CA with the hub's
signing CA — the hub's admin trust policy is a separate
fingerprint-allow-list and/or independent admin-CA set
(see [acme-server/docs/admin-api.md §Trust policy](acme-server/docs/admin-api.md)).

**In a hub session** (after `Connect`) you get:

- 📜 **Browse certificates** — list with `V` to toggle "only non-revoked",
  `D` to revoke (operator role).
- 👥 **Browse accounts** — list with `B` to ban / unban an issuer account
  (owner role). Ban cascades: every valid cert that account holds is
  revoked with `reason=privilegeWithdrawn`, every open order is cancelled,
  all wrapped in one DB transaction. Unban does NOT restore revoked certs.
- 📊 **Stats dashboard** — total/valid/invalid/expired orders, success
  rate, color stacked bar, top problem types, top failing identifiers,
  recent buckets sparkline.
- 📋 **Audit log** — filterable view (all / admin actions / revokes /
  cascade revokes / issuance / admin issuance / ca.verify).
- 🔑 **Verify CA private key** — proof-of-possession. TUI generates a
  nonce, hub signs `SHA-256("secutor-ca-verify-v1" || nonce)` with the CA
  private key, TUI verifies locally against the expected CA public key
  (sourced from a context cert or a .pem file). Detects key swaps / wrong
  intermediate / failed-to-promote staging.
- 🔄 **Rotate CA / re-sign leaves** — stage a new CA candidate (from a
  context CA with a stored key, or from a `.skb` bundle), promote it
  atomically, rollback within the configured window. Kick a background
  reissue job ("re-sign all active leaves") and watch its progress
  (`C` cancels).

See [acme-server/docs/ca-rotation.md](acme-server/docs/ca-rotation.md) and
[acme-server/docs/server-managed-dns.md](acme-server/docs/server-managed-dns.md)
for the server-side flows these screens drive.

## Keyboard

| Key | Action |
| --- | --- |
| `↑` `↓` / Tab | Navigate items / fields |
| `Enter` | Open / submit |
| `Esc` | Back / cancel |
| `/` | Filter the current list (certificates, SSH keys, profiles, contexts) — type to narrow, `Esc` clears |
| `E` | Export (on cert details) |
| `P` | Make P12 profile (on cert details) |
| `V` | Verify (on cert details) |
| `M` | Manage issuer — attach to a CA or re-sign with a different one (on cert details) |
| `T` | Transfer entity to `.skb` file or another context (on cert / SSH key / profile) |
| `R` | Revoke / Unrevoke (on cert details, non-root) |
| `D` | Delete (on lists) |
| `B` | Ban / Unban account (on remote accounts list) |
| `F` | Cycle filter (on remote audit log) |
| `C` | Cancel job (on job progress) |
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
npm test             # runs the full test suite (requires openssl + ssh-keygen on PATH)
npm run build        # emits dist/
node dist/cli.js     # run the build
```

`npm test` runs through Node's built-in `node:test` runner over TypeScript sources via `tsx`. Several tests shell out to `openssl verify` / `openssl x509 -text` and `ssh-keygen -l` / `-y` for end-to-end validation; tests that need a tool that isn't on `PATH` skip rather than fail.

## Technical overview

### Stack

| Layer | Tech |
| --- | --- |
| Runtime | Node.js ≥ 18.17 (uses `node:crypto`, `node:test`) |
| Language | TypeScript 5.5 (strict, ESM, NodeNext) |
| UI | [Ink](https://github.com/vadimdemedes/ink) (React-in-the-terminal) + custom mouse / F-key proxy |
| Storage | [`better-sqlite3`](https://github.com/WiseLibs/better-sqlite3) — synchronous, native binding |
| Crypto | [`node-forge`](https://github.com/digitalbazaar/forge) for ASN.1 / RSA / PKCS#12; `node:crypto` for everything else (ECDSA, Ed25519, X25519, PKCS#8 key encryption, file signing, SSH wire format) |
| Tests | `node:test`, shells out to `openssl` and `ssh-keygen` for interop checks |

### Project layout

```
src/
├── cli.tsx                # entrypoint: dispatches to subcommands, otherwise starts the TUI
├── cli/
│   └── commands.ts        # non-interactive `secutor sign` / `secutor verify` (see Non-interactive CLI in README)
├── app.tsx                # screen router
├── certs/
│   ├── core.ts            # X.509 builders: buildRootCa / buildIntermediateCa / buildLeafCert / resignCertificateCore
│   ├── keys.ts            # KeyAlgorithm enum, key generation, PKCS#8 encrypt/decrypt, algorithm detection
│   ├── manualBuilder.ts   # ASN.1 cert builder for non-RSA keys (ECDSA / Ed25519) + parseCertCompat helper
│   ├── generator.ts       # high-level CRUD: createCA, issueCert, renewCertificate, buildCRL, buildP12, …
│   ├── signing.ts         # file / application signing — detached manifest + self-describing bundle
│   ├── importer.ts        # PEM / PKCS#12 import + chain ordering
│   ├── parser.ts          # cert field extraction for the UI
│   ├── audit.ts           # cross-row sanity checks (drift, orphan, dn-mismatch, signature-invalid…)
│   ├── verify.ts          # chain + revocation + SNI verification
│   ├── expiry.ts          # not-before/not-after classification, color/icon
│   └── configExport.ts    # nginx / Traefik (file-provider, ACME) bundle generators
├── ssh/
│   └── sshKeys.ts         # SSH identity-key generation, OpenSSH wire format, OpenSSH v1 private export, ~/.ssh helper
├── utils/
│   └── clipboard.ts       # cross-platform copy via pbcopy / xclip / xsel / wl-copy / clip
├── components/            # ink components (Menu with `/` search, Form, FileExplorer, …)
├── i18n/
│   ├── LocaleProvider.tsx
│   └── locales/           # en.ts, ru.ts
├── input/                 # mouse regions + F-key proxy + raw stdin shim
├── screens/               # one file per screen
├── state/                 # AppContext (router stack, toasts)
└── storage/
    ├── db.ts              # SQLite open/close, schema, encryption-at-rest, migrations
    ├── crypto.ts          # AES-256-GCM context encryption (PBKDF2-SHA-256, 200k iters)
    ├── repos.ts           # certRepo, profileRepo, sshKeyRepo (CRUD)
    ├── contextStore.ts    # ~/.secutor/meta.json registry of named contexts
    └── paths.ts           # SECUTOR_HOME layout
test/
├── cert-generation.test.ts   # RSA cert chains, openssl verify, SAN encoding, serial sign-bit
├── algorithms.test.ts        # ECDSA P-256/P-384, Ed25519, mixed-algorithm chains, re-sign across algos
├── ca-password.test.ts       # passphrase-protected CA keys: issue, intermediate, re-sign, ECDSA + password
├── signing.test.ts           # sign/verify across all algorithms, detached / bundled, tamper detection, fingerprint pinning
├── ssh.test.ts               # OpenSSH wire format, ssh-keygen interop, OpenSSH v1 private export, ~/.ssh perms
├── pkcs12.test.ts            # PKCS#12 build / parse round-trips across algorithms
├── audit.test.ts             # store-level findings (parse-error, key-mismatch, meta-drift, issuer-* …)
└── expiry.test.ts            # ok / expiring-soon / expired / not-yet-valid classifier
```

### How non-RSA X.509 signing works

`node-forge` natively signs only RSA X.509 certificates. To support ECDSA P-256/P-384 and Ed25519, `manualBuilder.ts` does the following:

1. Build a placeholder forge certificate with a throwaway RSA key so forge correctly encodes the `Name` (subject/issuer DNs) and the `Extensions` block.
2. Override `cert.generateSubjectKeyIdentifier()` so the SKI is computed from the **real** subject public key (SHA-1 of the SubjectPublicKey BIT STRING contents, RFC 5280 §4.2.1.2 method 1) rather than from the placeholder.
3. Call `cert.sign(dummyRsaKey, sha256)` so forge populates `siginfo` — required by `getTBSCertificate`.
4. Extract `TBSCertificate` ASN.1, swap two fields:
   - `signature` (field index 2) → an `AlgorithmIdentifier` matching the signer's real algorithm (`ecdsa-with-SHA256` / `ecdsa-with-SHA384` / Ed25519 with no parameters).
   - `subjectPublicKeyInfo` (field index 6) → the real SPKI parsed from a node:crypto export.
5. Sign the modified TBS DER with `crypto.sign(hash, tbsDer, signerKey)` — `null` hash for Ed25519, `sha256` / `sha384` for ECDSA, `sha256` for RSA.
6. Wrap `{tbs, AlgorithmIdentifier, BIT STRING signature}` in the outer `Certificate` SEQUENCE and PEM-encode.

A symmetric helper `parseCertCompat()` lets the rest of the codebase read non-RSA cert PEMs through forge by swapping in a dummy RSA SPKI before parsing — every field except `cert.publicKey` parses correctly, which is enough for subject/issuer/extension introspection.

CRL signing follows the same pattern: `buildCRL` detects the CA's key type via `node:crypto` and emits the matching `AlgorithmIdentifier` and signature.

### Storage schema

```sql
CREATE TABLE certificates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL CHECK(type IN ('ca','server','client')),
  common_name TEXT NOT NULL,
  organization TEXT,
  issuer_id INTEGER REFERENCES certificates(id) ON DELETE SET NULL,
  serial TEXT NOT NULL,
  not_before TEXT NOT NULL,
  not_after TEXT NOT NULL,
  san TEXT,
  cert_pem TEXT NOT NULL,
  key_pem TEXT NOT NULL DEFAULT '',     -- plain PKCS#8 *or* encrypted PKCS#8 (AES-256-CBC)
  fingerprint TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  revocation_reason TEXT
);

CREATE TABLE profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  cert_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
  format TEXT NOT NULL DEFAULT 'p12',
  friendly_name TEXT,
  data BLOB NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE ssh_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  algorithm TEXT NOT NULL,              -- ssh-ed25519, ssh-rsa-2048, ssh-ecdsa-p256, …
  comment TEXT,
  public_key TEXT NOT NULL,             -- one-line OpenSSH format
  private_key TEXT NOT NULL,            -- PKCS#8 PEM, possibly encrypted
  encrypted INTEGER NOT NULL DEFAULT 0,
  fingerprint TEXT NOT NULL,            -- SHA256:…
  created_at TEXT NOT NULL
);
```

For an encrypted context, the entire SQLite file is AES-256-GCM-encrypted at rest with a key derived via PBKDF2-SHA-256 (200 000 iterations, 16-byte salt). The plaintext SQLite file lives in `os.tmpdir()` with mode `0600` for the duration of the session and is re-encrypted on every write.

### Signature manifest format

The detached `.sig` file (and the embedded blob inside a bundle) is a small JSON document:

```json
{
  "v": 1,
  "alg": "ecdsa-p256",
  "hash": "sha256",
  "dataHash": "<hex SHA-256 of the signed bytes>",
  "signature": "<base64-encoded DER signature, or raw 64 bytes for Ed25519>",
  "signer": {
    "certPem": "-----BEGIN CERTIFICATE----- … (optional)",
    "fingerprint": "<hex SHA-256 of the signer cert DER, optional>",
    "commonName": "<subject CN, optional>"
  },
  "signedAt": "2026-05-26T12:34:56.000Z"
}
```

The bundle layout is a 15-byte magic (`SECUTORSIG\x01`) + uint32-BE manifest length + manifest JSON + raw data, all in one buffer.

### Tests

```
$ npm test
…
# tests 160
# pass  160
# fail  0
```

The suite covers:

- RSA cert generation, SAN encoding, serial sign-bit handling, and `openssl verify` interop
- Modern-algorithm coverage — ECDSA P-256, P-384, Ed25519, mixed-algorithm chains, three-tier intermediate chains, re-signing across algorithms
- CA-passphrase encryption envelope, mandatory-password enforcement, wrong-password rejection, intermediate with a different passphrase, ECDSA + passphrase, re-sign with encrypted CA
- PKCS#12 build / parse round-trips across algorithms
- File-signing — sign/verify across all signing algorithms, encrypted signer key, detached `.sig`, bundled format, signer mismatch, fingerprint pinning, JSON round-trip
- SSH-key tests — OpenSSH wire format for all algorithms, `ssh-keygen -lf` fingerprint match, `ssh-keygen -y -f` reads the OpenSSH v1 private-key output, encrypted-key round-trip, `~/.ssh` export with `0600` perms
- Store-level audit findings (parse-error, key-mismatch, meta-drift, issuer-* …) and expiry classification

## Security notes

- Default leaf signature hash is SHA-256 for RSA / ECDSA P-256, SHA-384 for ECDSA P-384, and Ed25519's intrinsic hash for Ed25519. SHA-1 is never used for signing certificates (it's only used internally to compute Subject/Authority Key Identifiers per RFC 5280, which is the standard practice).
- CA private keys can be stored either plaintext or encrypted as PKCS#8 with AES-256-CBC. The passphrase is **never** persisted — every CA operation (issue, re-sign, renew, CRL, P12) prompts for it.
- The encrypted-context password derives a separate AES-256-GCM key (PBKDF2-SHA-256, 200 000 iterations). A wrong password fails AEAD verification rather than yielding garbage.
- Self-signed roots cannot be revoked (no issuer to revoke against). Intermediates and leaves can.
- Storage files are written with mode `0600` on POSIX (the same applies to `~/.ssh/<name>` exports — file `0600`, dir `0700`). Windows ignores POSIX modes; rely on user-profile ACLs.
- This is a local PKI tool. It does **not** publish OCSP responders or distribute CRLs over HTTP — you have to ship the exported `.crl` to relying parties yourself.
- *Attach to existing CA* is a DB-only relink — it does **not** validate that the picked CA actually signed the certificate. It's a recovery aid; verification (`V`) still runs the cryptographic check and will reject an incorrect attachment.
- *Re-sign* changes the cert's signature, issuer, AKI and serial. Anyone holding a copy of the **old** cert (or a CRL that listed it) won't recognise the new one — distribute the re-signed cert to relying parties.
- File-signature verification is offline. The verifier extracts the signer cert from the manifest (or accepts a pinned cert PEM and/or fingerprint from the caller) and runs `crypto.verify`. There is currently no built-in revocation check at signature-verify time — pair signatures with a separate CRL distribution if you need timely revocation.
- `secutor` does not phone home, ship telemetry, or contact external services. The only network I/O is npm's `prebuild-install` during the initial `npm install -g secutor` (to download `better-sqlite3` prebuilt binaries from GitHub Releases).

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) for the full text.

Copyright © 2026 kamighost.

This software bundles or depends on third-party packages with their own licenses; see `package.json` and each package's `LICENSE` file in `node_modules/` after install. Notable dependencies and their upstream licenses:

| Package | License |
| --- | --- |
| `node-forge` | (BSD-3-Clause OR GPL-2.0) |
| `better-sqlite3` | MIT |
| `ink`, `ink-select-input`, `ink-spinner`, `ink-text-input` | MIT |
| `react` | MIT |
