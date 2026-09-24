#!/usr/bin/env python3
"""
Smoke test for hekate_sha256check.

Usage: smoke.py <command...>
  e.g. smoke.py ./hekate_sha256check
       smoke.py wine ./hekate_sha256check.exe
"""

import hashlib
import os
import subprocess
import sys
import tempfile

CHUNK = 4 * 1024 * 1024


def write_part(path, size, chunk_size=CHUNK):
    data = os.urandom(size)
    with open(path, "wb") as f:
        f.write(data)
    with open(path + ".sha256sums", "w", newline="\n") as f:
        f.write(f"# chunksize: {chunk_size}\n")
        for off in range(0, size, chunk_size):
            f.write(hashlib.sha256(data[off:off + chunk_size]).hexdigest() + "\n")
    return data


def main():
    cmd = sys.argv[1:]
    if not cmd:
        sys.exit(__doc__)

    failures = 0

    def check(name, args, want_code, want_text=None):
        nonlocal failures
        r = subprocess.run(cmd + args, capture_output=True)
        out = (r.stdout + r.stderr).decode("utf-8", "replace")
        ok = r.returncode == want_code and (want_text is None or want_text in out)
        print(f"{'PASS' if ok else 'FAIL'}: {name} (exit {r.returncode}, want {want_code})")
        if not ok:
            print("  " + out.replace("\n", "\n  "))
            failures += 1

    with tempfile.TemporaryDirectory() as tmp:
        # Non-ASCII directory checks Unicode path handling.
        d = os.path.join(tmp, "бэкап 日本")
        os.mkdir(d)
        p = lambda name: os.path.join(d, name)

        # 3 full chunks + short tail.
        write_part(p("rawnand.bin.00"), 3 * CHUNK + 512 * 1024)
        write_part(p("rawnand.bin.01"), 2 * CHUNK)

        check("valid parts", [p("rawnand.bin.00"), p("rawnand.bin.01")], 0, "2 of 2 file(s) verified OK")
        check("hash files are skipped", [p("rawnand.bin.00"), p("rawnand.bin.00.sha256sums")], 0,
              "1 of 1 file(s) verified OK")

        # Flip one byte in chunk 1.
        data = write_part(p("corrupt.bin"), 2 * CHUNK)
        with open(p("corrupt.bin"), "r+b") as f:
            f.seek(CHUNK + 1234)
            f.write(bytes([data[CHUNK + 1234] ^ 0xFF]))
        check("corrupted chunk", [p("corrupt.bin")], 1, "MISMATCH at chunk 1")

        write_part(p("truncated.bin"), 2 * CHUNK)
        with open(p("truncated.bin"), "r+b") as f:
            f.truncate(CHUNK)
        check("truncated file", [p("truncated.bin")], 1, "more entries than file chunks")

        write_part(p("short_hashes.bin"), 2 * CHUNK)
        with open(p("short_hashes.bin.sha256sums")) as f:
            lines = f.readlines()
        with open(p("short_hashes.bin.sha256sums"), "w", newline="\n") as f:
            f.writelines(lines[:-1])
        check("incomplete hash file", [p("short_hashes.bin")], 2, "incomplete or invalid")

        write_part(p("crlf.bin"), CHUNK + 1)
        with open(p("crlf.bin.sha256sums"), "rb") as f:
            raw = f.read()
        with open(p("crlf.bin.sha256sums"), "wb") as f:
            f.write(raw.replace(b"\n", b"\r\n"))
        check("CRLF hash file", [p("crlf.bin")], 0)

        with open(p("nohash.bin"), "wb") as f:
            f.write(b"\0" * 1024)
        check("missing hash file", [p("nohash.bin")], 2)

        with open(p("badheader.bin"), "wb") as f:
            f.write(b"\0" * 1024)
        with open(p("badheader.bin.sha256sums"), "w") as f:
            f.write("not a hash file\n")
        check("invalid header", [p("badheader.bin")], 2, "invalid header")

        check("no arguments", [], 2)

    if failures:
        sys.exit(f"{failures} test(s) failed")
    print("All tests passed")


if __name__ == "__main__":
    main()
