# hekate_sha256check

Verifies [hekate](https://github.com/CTCaer/hekate) / Nyx eMMC and emuMMC backups
on a PC, using the `.sha256sums` files Nyx writes next to each backup file.

Nyx does not hash the whole file. It stores one SHA256 per 4 MiB chunk, so
`sha256sum -c` can't check these files. This tool can.

## Creating the hash files

In Nyx, open **Nyx Settings** and set **Data Verification** to **Full (Hashes)**
(`verification=3` in `bootloader/nyx.ini`), then make the backup. Every backup
file gets a hash file next to it:

```
backup/<emmc_sn>/
├── BOOT0
├── BOOT0.sha256sums
├── rawnand.bin.00
├── rawnand.bin.00.sha256sums
├── rawnand.bin.01
├── rawnand.bin.01.sha256sums
└── ...
```

The hash file format:

```
# chunksize: 4194304
<sha256 of bytes 0 .. 4 MiB>
<sha256 of bytes 4 .. 8 MiB>
...
```

Chunks are counted from the start of each file, not the whole dump. The last
chunk may be shorter than 4 MiB.

## Usage

```sh
hekate_sha256check rawnand.bin.00 rawnand.bin.01 ...
hekate_sha256check rawnand.bin.*        # .sha256sums files are skipped
hekate_sha256check BOOT0 BOOT1 rawnand.bin.*
```

On Windows, wildcards work in `cmd.exe` and PowerShell, and so do non-ASCII paths:

```bat
hekate_sha256check-windows-x86_64.exe D:\backup\rawnand.bin.*
```

Example output:

```
rawnand.bin.00: OK (1024 chunks)
rawnand.bin.01: MISMATCH at chunk 1 (offset 0x400000, 4194304 bytes)
rawnand.bin.01: FAILED (1024 chunks)

1 of 2 file(s) verified OK
```

The tool checks every chunk, so it reports every bad one, not just the first.
If a file is shorter than its hash file says, it is reported as truncated.

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | All files match |
| 1 | At least one chunk does not match, or a file is truncated |
| 2 | I/O error, missing or invalid hash file, or bad arguments |

## Downloads

Prebuilt binaries are attached to [Releases](../../releases), together with
`SHA256SUMS`:

| Platform | File |
|----------|------|
| Linux x86_64 (static) | `hekate_sha256check-linux-x86_64` |
| Linux aarch64 (static) | `hekate_sha256check-linux-aarch64` |
| Windows x86_64 | `hekate_sha256check-windows-x86_64.exe` |
| Windows ARM64 | `hekate_sha256check-windows-arm64.exe` |
| macOS (Intel and Apple Silicon) | `hekate_sha256check-darwin-universal` |

On Linux and macOS, run `chmod +x` on the downloaded file first. macOS may
block unsigned binaries. To allow it, run
`xattr -d com.apple.quarantine hekate_sha256check-darwin-universal`.

## Building

It's a single C file with no dependencies (SHA256 is built in).

```sh
# Linux / macOS
cc -O2 -Wall -o hekate_sha256check hekate_sha256check.c

# Linux, fully static
musl-gcc -O2 -Wall -static -s -o hekate_sha256check hekate_sha256check.c

# Windows x86_64 (MinGW-w64), -municode is required
x86_64-w64-mingw32-gcc -O2 -Wall -static -s -municode -o hekate_sha256check.exe hekate_sha256check.c

# Windows ARM64 (llvm-mingw)
aarch64-w64-mingw32-clang -O2 -Wall -static -s -municode -o hekate_sha256check.exe hekate_sha256check.c

# macOS universal
clang -O2 -Wall -arch x86_64 -arch arm64 -o hekate_sha256check hekate_sha256check.c
```

## Tests

```sh
python3 tests/smoke.py ./hekate_sha256check
python3 tests/smoke.py wine ./hekate_sha256check.exe
```

CI builds every platform and runs the smoke test on it natively. Publishing
a GitHub release uploads the binaries to it.

## License

[VibeCoded AI-Slop License v1.0](LICENSE). This code was written by an AI.
