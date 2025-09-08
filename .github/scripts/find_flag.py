#!/usr/bin/env python3
# .github/scripts/find_flag.py
# Reads ./checker (env BIN) and tries to find a BHFlagY{...} candidate by decoding repeating-xor keys
# and small post-transforms, then runs ./checker <candidate> to see if it accepts.

import os, sys, re, subprocess, itertools, time

BIN = os.environ.get("BIN", "./checker")
if not os.path.exists(BIN):
    print("ERROR: checker binary not found at", BIN)
    sys.exit(2)

data = open(BIN, "rb").read()
prefix = b"BHFlagY{"
allowed_inner = set(range(48,58)) | set(range(65,91)) | set(range(97,123)) | {95,45}
MAX_KEYLEN1 = 32
MAX_KEYLEN2 = 8
SCAN_LEN = 400

def decode_with_key(data, pos, key):
    out = bytearray()
    for i in range(SCAN_LEN):
        if pos + i >= len(data):
            break
        out.append(data[pos+i] ^ key[i % len(key)])
    return bytes(out)

def run_checker(candidate):
    try:
        p = subprocess.run([BIN, candidate], capture_output=True, text=True, timeout=6)
        out = (p.stdout or "") + (p.stderr or "")
        return out.strip()
    except Exception as e:
        return "ERROR: " + str(e)

def test_and_report(flag_bytes):
    flag = flag_bytes.decode("latin1")
    print("Testing candidate:", flag)
    out = run_checker(flag)
    print("checker output:", repr(out))
    if "NOPE" not in out:
        print("\n\nFOUND FLAG:", flag, "\n\n")
        return True
    return False

print("Scanning for prefix-candidates (this may take ~30-90s)...")
candidates = []
# find prefix positions where a repeating XOR key1 (1..MAX_KEYLEN1) can map bytes -> prefix
for pos in range(0, max(1, len(data) - len(prefix))):
    for keylen in range(1, MAX_KEYLEN1 + 1):
        if pos + len(prefix) > len(data):
            continue
        key = [None] * keylen
        ok = True
        for i in range(len(prefix)):
            kidx = i % keylen
            val = data[pos+i] ^ prefix[i]
            if key[kidx] is None:
                key[kidx] = val
            elif key[kidx] != val:
                ok = False
                break
        if not ok:
            continue
        keyb = bytes(k if k is not None else 0 for k in key)
        dec = decode_with_key(data, pos, keyb)
        if dec.startswith(prefix):
            candidates.append((pos, keyb, dec))
    if len(candidates) > 300:
        break

print("Found", len(candidates), "candidates. Testing them now...")

# Test each candidate by trying small post transforms to reveal printable payload
for pos, key1, dec in candidates:
    print("=== candidate pos=%d keylen=%d ===" % (pos, len(key1)))
    inner = dec[len(prefix):]
    # 1) literal printable payload
    if b"}" in inner[:200]:
        endidx = inner.find(b"}")
        payload = inner[:endidx]
        cand = prefix + payload + b"}"
        if re.match(br"^BHFlagY\{[A-Za-z0-9_\-]{4,200}\}$", cand):
            if test_and_report(cand):
                sys.exit(0)

    # 2) single-byte xor
    for k in range(256):
        t = bytes([b ^ k for b in inner[:200]])
        if b"}" in t[:200]:
            end = t.find(b"}")
            payload = t[:end]
            if 4 <= len(payload) <= 200 and all(c in allowed_inner for c in payload):
                cand = prefix + payload + b"}"
                if test_and_report(cand):
                    sys.exit(0)

    # 3) small repeating key derived by intersection (length 1..MAX_KEYLEN2)
    for L2 in range(1, MAX_KEYLEN2+1):
        pools = [set(range(256)) for _ in range(L2)]
        limit = min(120, len(inner))
        for j in range(limit):
            idx = j % L2
            encb = inner[j]
            pools[idx] &= set((encb ^ v) & 0xFF for v in (allowed_inner | {125}))
            if not pools[idx]:
                break
        if any(len(s) == 0 for s in pools):
            continue
        pools_l = [sorted(list(s))[:28] for s in pools]
        total = 1
        for p in pools_l:
            total *= len(p)
        if total > 2000000:
            continue
        for combo in itertools.product(*pools_l):
            key2 = bytes(combo)
            dec2 = bytes((inner[i] ^ key2[i % L2]) for i in range(len(inner)))
            if b"}" not in dec2[:200]:
                continue
            endidx = dec2.find(b"}")
            payload = dec2[:endidx]
            if 4 <= len(payload) <= 200 and all(c in allowed_inner for c in payload):
                cand = prefix + payload + b"}"
                if test_and_report(cand):
                    sys.exit(0)

    # 4) rotations + 1-byte xor
    def rol(b, n): return ((b << n) & 0xFF) | (b >> (8-n))
    def ror(b, n): return (b >> n) | ((b << (8-n)) & 0xFF)
    for n in range(8):
        rot = bytes(rol(b, n) for b in inner[:200])
        for k in range(256):
            t = bytes(b ^ k for b in rot)
            if b"}" in t[:200]:
                endidx = t.find(b"}")
                payload = t[:endidx]
                if 4 <= len(payload) <= 200 and all(c in allowed_inner for c in payload):
                    cand = prefix + payload + b"}"
                    if test_and_report(cand):
                        sys.exit(0)
        rot = bytes(ror(b, n) for b in inner[:200])
        for k in range(256):
            t = bytes(b ^ k for b in rot)
            if b"}" in t[:200]:
                endidx = t.find(b"}")
                payload = t[:endidx]
                if 4 <= len(payload) <= 200 and all(c in allowed_inner for c in payload):
                    cand = prefix + payload + b"}"
                    if test_and_report(cand):
                        sys.exit(0)

print("No passing candidate detected in this run.")
sys.exit(1)
