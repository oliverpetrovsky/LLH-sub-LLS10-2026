# VaultFS

****An encrypted filesystem that stays safe when the attacker owns the disk.****

Your files live in a folder you unlock with a password. Everything actually
stored is AES-256-GCM ciphertext in opaque, randomly-named objects. An attacker
who can read, copy, alter, delete, and *roll back* every stored byte — but who
does not have your password or your running process — learns nothing useful and
cannot change your data without you noticing.

VaultFS is written from scratch in C over OpenSSL and talks the **raw Linux FUSE
protocol directly** (no libfuse) — so the filesystem is genuinely its own work.

```
$ vaultfs init /srv/vault alice                 # create a volume
$ vaultfs --user alice mount /srv/vault ~/vault # unlock and mount
$ echo "secret" > ~/vault/notes.txt             # just a folder
$ cat /srv/vault/objects/*                       # on disk: ciphertext only
```

---

## What it guarantees (mapped to the brief)

| # | Goal | How VaultFS does it |
|---|------|---------------------|
| 1 | **Work like a real folder** | A FUSE mount; `cat`, `cp`, `vim`, `mkdir`, `rm`, `git` operate on the decrypted view unchanged. |
| 2 | **Give nothing away** | File contents, names and directory structure are all encrypted; objects have random names; blocks are fixed 4 KiB. |
| 3 | **Catch tampering** | Every block and the catalog are AES-256-GCM; any altered byte fails authentication → `EIO`. |
| 4 | **Notice old copies** | A monotonic version counter inside the authenticated catalog is checked against a tiny trusted **anchor**; restoring an older copy of the whole volume is detected as a rollback. |
| 5 | **Protect the password** | scrypt (N=2¹⁵) password hashing; a wrong password is refused cleanly; `passwd` re-wraps only your key, not your data. |
| 6 | **Multiple users** | Each user has their own password and X25519 keypair; files carry a random key wrapped per authorized user; `share`/`revoke` work per file, and revoke **rotates the key** so the removed user loses everything written afterwards — without re-encrypting the volume. |
| 7 | **Keep secrets safe while running** | Keys live only in memory, are `mlock`ed and wiped (`OPENSSL_cleanse`); nothing secret is logged. |
| 8 | **Survive failure** | Content is copy-on-write; the catalog is committed by atomic `rename`+`fsync`; an interrupted write leaves the last good version intact. |
| 9 | **Hold up under attack** | All attacker-supplied data is parsed with a bounds-checked reader that fails closed, and nothing is trusted before its GCM tag is verified (authenticate-before-use). |

See [`DESIGN.md`](DESIGN.md) for the cryptographic construction and the trust model.

## How it's built

```
password ─scrypt→ UKEK ─AES-GCM→ user X25519 private key
                                     │ sealed-box
                                     ▼
                        Volume Metadata Key (VMK) ─AES-GCM→ catalog (tree + metadata)
                                                                 │ per-file sealed-box
                                                                 ▼
                                                     file key ─AES-GCM→ 4 KiB data blocks
```

* **crypto.c** — scrypt, AES-256-GCM, X25519 sealed boxes (ECIES+HKDF), SHA-256.
* **util.c** — atomic writes and a bounds-checked (de)serializer.
* **vault.c / vault_ops.c** — the engine: volume/users/catalog/files/sharing/rollback.
* **fuse_lowlevel.c** — the mount, written against the raw `/dev/fuse` protocol.
* **cli.c** — the `vaultfs` command.

## Build

Dependencies: a C compiler, OpenSSL ≥ 3.0 (`libcrypto`), and for mounting the
`fuse3` userspace helper (`fusermount3`) plus the `fuse` kernel module.

```bash
# Debian/Ubuntu
sudo apt install build-essential libssl-dev fuse3
# Fedora
sudo dnf install gcc openssl-devel fuse3

make                 # builds ./vaultfs
```

Tested on Ubuntu 24.04 and Debian 12 (x86-64). No kernel patches; the raw FUSE
protocol has been stable for many years.

## Use

```bash
vaultfs init   <backing> <admin>              # create a volume (prompts password)
vaultfs --user <u> mount  <backing> <dir>     # unlock and mount as a folder
vaultfs --user <u> adduser <backing> <name>   # add a user (admin only)
vaultfs --user <u> deluser <backing> <name>   # remove a user (rotates the VMK)
vaultfs --user <u> passwd  <backing>          # change your own password
vaultfs --user <u> share   <backing> <path> <user>   # grant access to a file
vaultfs --user <u> revoke  <backing> <path> <user>   # revoke (rotates the file key)
vaultfs --user <u> ls|mkdir|put|get|rm|mv|access|fsck|gc ...   # offline operations
```

The password is read from `$VAULTFS_PASSWORD` if set, else prompted. The trusted
rollback **anchor** directory is `--anchor DIR`, else `$VAULTFS_ANCHOR_DIR`, else
`~/.config/vaultfs`. Keep it on storage the attacker does not control (see below).

### Example

```bash
export VAULTFS_ANCHOR_DIR=~/.config/vaultfs
vaultfs init /srv/vault alice                     # password: ••••
vaultfs --user alice adduser /srv/vault bob
vaultfs --user alice mount /srv/vault ~/vault &
echo "quarterly numbers" > ~/vault/report.txt
vaultfs --user alice share /srv/vault /report.txt bob     # bob can now read it
vaultfs --user alice revoke /srv/vault /report.txt bob    # ...and now he can't
```

## The trust model in one paragraph

The attacker controls every byte of the **backing directory** and may keep and
restore old snapshots of it. They do **not** have your password or access to the
running process. Confidentiality and integrity rest entirely on your password
and the in-memory keys. Rollback detection needs one extra thing: a small piece
of **trusted, monotonic state** — the anchor file (a volume id, a counter, and a
hash). This is the minimal trusted state any rollback-resistant design needs (a
hardware monotonic counter or TPM would serve the same role). Everything else is
untrusted. If you point the anchor inside the backing directory, you keep
confidentiality and tamper-detection but lose whole-volume rollback detection.

## Evidence

```bash
make check      # builds, runs the C engine tests, then the black-box suite
```

* `test_engine` — API-level tests: auth, multi-block IO, partial writes,
  truncate, rename, sharing, revocation, password change.
* `tests/run_tests.sh` — black-box security tests driven through the CLI and a
  real mount: on-disk confidentiality, data **and** catalog tamper detection,
  whole-volume rollback detection, wrong-password refusal, share/revoke, crash
  safety, and ordinary tools operating on the mounted folder.

## Limitations (honest scope)

* **Metadata to co-tenants.** Enrolled users share the catalog key, so they can
  see the directory structure and file *names* (never contents without the file
  key). Hiding metadata per-user would use per-user catalogs — a documented
  extension. Against the *external* attacker (the brief's threat model) names and
  structure are fully encrypted.
* **Insider integrity.** Integrity is under the shared VMK, which is sufficient
  against the external attacker. Defending integrity against a *malicious
  enrolled user* would add per-user signatures over the catalog.
* **Size.** Objects are padded to 4 KiB block granularity; the last block and the
  object count still reveal file size to that granularity.
* **Performance.** The catalog is rewritten on each metadata commit — simple and
  crash-safe, and fine at these scales; a journaled B-tree would scale further.

These are deliberate, documented trade-offs, not gaps in the threat model the
brief defines.

## Demo

A 5-minute walkthrough is in [`DEMO.md`](DEMO.md) (`scripts/demo.sh` runs it).

## License

MIT — see [LICENSE](LICENSE).
