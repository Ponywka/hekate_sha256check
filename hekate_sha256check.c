/*
 * hekate_sha256check - verifies hekate/Nyx eMMC backup parts against their
 * <file>.sha256sums, created by "Full (Hashes)" verification.
 *
 * Hash file format (see hekate, nyx/nyx_gui/frontend/fe_emmc_tools.c):
 *   # chunksize: 4194304
 *   <sha256 hex of chunk 0>
 *   <sha256 hex of chunk 1>
 *   ...
 * Each chunk is NUM_SECTORS_PER_ITER (8192) * 512 = 4 MiB of the file,
 * the last one may be shorter. Hashes are per file, not per whole dump.
 *
 * Build (Linux):   cc -O2 -Wall -o hekate_sha256check hekate_sha256check.c
 * Build (Windows): x86_64-w64-mingw32-gcc -O2 -Wall -static -municode -o hekate_sha256check.exe hekate_sha256check.c
 * Usage: hekate_sha256check rawnand.bin.00 rawnand.bin.01 ...
 *        hekate_sha256check rawnand.bin.*   (.sha256sums files are skipped)
 */

#define _FILE_OFFSET_BITS 64
#ifdef _WIN32
/* C99 printf (%llu, %zu) instead of the old msvcrt one. */
#define __USE_MINGW_ANSI_STDIO 1
#endif

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#ifndef UNICODE
#error "Build with -municode, wmain is needed for non-ASCII paths."
#endif
#include <io.h>
#include <windows.h>
/* Older MinGW headers map these to fseeko64/ftello64 themselves. */
#undef fseeko
#undef ftello
#define fseeko _fseeki64
#define ftello _ftelli64
#define isatty _isatty
#define fileno _fileno
/* cmd.exe does not expand wildcards, let the MinGW CRT do it. */
int _dowildcard = -1;
#else
#include <unistd.h>
#endif

/* ---------- Platform helpers ---------- */

/* Paths are UTF-8 internally, Windows needs them as UTF-16. */
static FILE *xfopen(const char *path, const char *mode)
{
#ifdef _WIN32
	wchar_t wpath[4096], wmode[8];

	if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 4096) ||
	    !MultiByteToWideChar(CP_UTF8, 0, mode, -1, wmode, 8)) {
		errno = ENAMETOOLONG;
		return NULL;
	}
	return _wfopen(wpath, wmode);
#else
	return fopen(path, mode);
#endif
}

/* Terminal columns taken by a UTF-8 string (one per code point). */
static int utf8_width(const char *s)
{
	int n = 0;
	for (; *s; s++)
		if (((unsigned char)*s & 0xC0) != 0x80)
			n++;
	return n;
}

/* ---------- Minimal SHA-256 ---------- */

typedef struct {
	uint32_t h[8];
	uint64_t len;
	uint8_t buf[64];
	size_t buf_len;
} sha256_ctx;

static const uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(sha256_ctx *c, const uint8_t *p)
{
	uint32_t w[64], a, b, d, e, f, g, h, cc, t1, t2;
	int i;

	for (i = 0; i < 16; i++)
		w[i] = (uint32_t)p[i * 4] << 24 | (uint32_t)p[i * 4 + 1] << 16 |
		       (uint32_t)p[i * 4 + 2] << 8 | p[i * 4 + 3];
	for (; i < 64; i++) {
		uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
	e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
	for (i = 0; i < 64; i++) {
		t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
		t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & cc) ^ (b & cc));
		h = g; g = f; f = e; e = d + t1;
		d = cc; cc = b; b = a; a = t1 + t2;
	}
	c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
	c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha256_init(sha256_ctx *c)
{
	static const uint32_t iv[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};
	memcpy(c->h, iv, sizeof(iv));
	c->len = 0;
	c->buf_len = 0;
}

static void sha256_update(sha256_ctx *c, const uint8_t *p, size_t n)
{
	c->len += n;
	if (c->buf_len) {
		size_t k = 64 - c->buf_len;
		if (k > n)
			k = n;
		memcpy(c->buf + c->buf_len, p, k);
		c->buf_len += k; p += k; n -= k;
		if (c->buf_len < 64)
			return;
		sha256_block(c, c->buf);
		c->buf_len = 0;
	}
	for (; n >= 64; p += 64, n -= 64)
		sha256_block(c, p);
	memcpy(c->buf, p, n);
	c->buf_len = n;
}

static void sha256_final(sha256_ctx *c, uint8_t out[32])
{
	uint64_t bits = c->len * 8;
	uint8_t pad = 0x80;
	int i;

	sha256_update(c, &pad, 1);
	pad = 0;
	while (c->buf_len != 56)
		sha256_update(c, &pad, 1);
	for (i = 7; i >= 0; i--) {
		uint8_t b = (uint8_t)(bits >> (i * 8));
		sha256_update(c, &b, 1);
	}
	for (i = 0; i < 8; i++) {
		out[i * 4]     = (uint8_t)(c->h[i] >> 24);
		out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
		out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
		out[i * 4 + 3] = (uint8_t)(c->h[i]);
	}
}

/* ---------- Verification ---------- */

static int hex_nibble(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* Parses "<64 hex chars>[\r]\n" into 32 bytes. Returns 0 on success. */
static int parse_hash_line(const char *line, uint8_t out[32])
{
	for (int i = 0; i < 64; i++) {
		int v = hex_nibble(line[i]);
		if (v < 0)
			return -1;
		if (i & 1)
			out[i >> 1] |= (uint8_t)v;
		else
			out[i >> 1] = (uint8_t)(v << 4);
	}
	const char *end = line + 64;
	if (*end == '\r')
		end++;
	return (*end == '\0' || *end == '\n') ? 0 : -1;
}

static int is_blank(const char *s)
{
	for (; *s; s++)
		if (*s != '\n' && *s != '\r' && *s != ' ' && *s != '\t')
			return 0;
	return 1;
}

static int progress_len;

/*
 * Erases the progress line, so messages start on a clean line.
 * Overwrites with spaces, as old Windows consoles lack ANSI escapes.
 */
static void clear_progress(void)
{
	if (progress_len) {
		fprintf(stderr, "\r%*s\r", progress_len, "");
		progress_len = 0;
	}
}

enum { RES_OK = 0, RES_MISMATCH = 1, RES_ERROR = 2 };

static int check_file(const char *path)
{
	char hash_path[4096];
	char line[256];
	uint8_t expected[32], actual[32];
	uint8_t *buf = NULL;
	FILE *fp = NULL, *hfp = NULL;
	uint64_t chunk_size, chunk = 0, offset = 0, file_size;
	int res = RES_OK;

	if (snprintf(hash_path, sizeof(hash_path), "%s.sha256sums", path) >= (int)sizeof(hash_path)) {
		fprintf(stderr, "%s: path too long\n", path);
		return RES_ERROR;
	}

	hfp = xfopen(hash_path, "r");
	if (!hfp) {
		fprintf(stderr, "%s: cannot open %s: %s\n", path, hash_path, strerror(errno));
		return RES_ERROR;
	}

	if (!fgets(line, sizeof(line), hfp) || strncmp(line, "# chunksize: ", 13)) {
		fprintf(stderr, "%s: invalid header in %s\n", path, hash_path);
		res = RES_ERROR;
		goto out;
	}
	chunk_size = strtoull(line + 13, NULL, 10);
	if (!chunk_size || chunk_size > (1ULL << 30)) {
		fprintf(stderr, "%s: bad chunk size in %s\n", path, hash_path);
		res = RES_ERROR;
		goto out;
	}

	fp = xfopen(path, "rb");
	if (!fp) {
		fprintf(stderr, "%s: cannot open: %s\n", path, strerror(errno));
		res = RES_ERROR;
		goto out;
	}
	fseeko(fp, 0, SEEK_END);
	file_size = (uint64_t)ftello(fp);
	fseeko(fp, 0, SEEK_SET);

	buf = malloc(chunk_size);
	if (!buf) {
		fprintf(stderr, "%s: out of memory\n", path);
		res = RES_ERROR;
		goto out;
	}

	while (offset < file_size) {
		size_t want = (size_t)(file_size - offset < chunk_size ? file_size - offset : chunk_size);
		size_t got = fread(buf, 1, want, fp);
		if (got != want) {
			clear_progress();
			fprintf(stderr, "%s: read error at chunk %llu\n", path, (unsigned long long)chunk);
			res = RES_ERROR;
			goto out;
		}

		sha256_ctx ctx;
		sha256_init(&ctx);
		sha256_update(&ctx, buf, got);
		sha256_final(&ctx, actual);

		if (!fgets(line, sizeof(line), hfp) || parse_hash_line(line, expected)) {
			clear_progress();
			fprintf(stderr, "%s: hash file incomplete or invalid at chunk %llu\n",
				path, (unsigned long long)chunk);
			res = RES_ERROR;
			goto out;
		}

		if (memcmp(expected, actual, 32)) {
			clear_progress();
			fprintf(stderr, "%s: MISMATCH at chunk %llu (offset 0x%llx, %zu bytes)\n",
				path, (unsigned long long)chunk, (unsigned long long)offset, got);
			res = RES_MISMATCH;
			/* Keep going to report every bad chunk. */
		}

		offset += got;
		chunk++;

		if (isatty(fileno(stderr))) {
			fprintf(stderr, "\r%s: %3llu%%", path,
				(unsigned long long)(offset * 100 / file_size));
			progress_len = utf8_width(path) + 6;
		}
	}
	clear_progress();

	/* Hash file must not have more chunks than the backup. */
	while (fgets(line, sizeof(line), hfp)) {
		if (!is_blank(line)) {
			fprintf(stderr, "%s: hash file has more entries than file chunks (file truncated?)\n", path);
			if (res == RES_OK)
				res = RES_MISMATCH;
			break;
		}
	}

	printf("%s: %s (%llu chunks)\n", path,
	       res == RES_OK ? "OK" : "FAILED", (unsigned long long)chunk);

out:
	free(buf);
	if (fp)
		fclose(fp);
	fclose(hfp);
	return res;
}

static int run(int argc, char **argv)
{
	int worst = RES_OK, failed = 0, total = 0;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s rawnand.bin.00 [rawnand.bin.01 ...]\n", argv[0]);
		return 2;
	}

	for (int i = 1; i < argc; i++) {
		/* Allow passing a glob like rawnand.bin.* which also matches hash files. */
		size_t len = strlen(argv[i]);
		if (len >= 11 && !strcmp(argv[i] + len - 11, ".sha256sums"))
			continue;

		total++;
		int r = check_file(argv[i]);
		if (r != RES_OK) {
			failed++;
			if (r > worst)
				worst = r;
		}
	}

	printf("\n%d of %d file(s) verified OK\n", total - failed, total);
	return worst;
}

#ifdef _WIN32
/* Wide entry point, so any Unicode path survives. Wildcards are expanded by the CRT. */
int wmain(int argc, wchar_t **wargv)
{
	char **argv = calloc((size_t)argc + 1, sizeof(char *));

	if (!argv)
		return 2;
	for (int i = 0; i < argc; i++) {
		int len = WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, NULL, 0, NULL, NULL);
		argv[i] = malloc(len > 0 ? (size_t)len : 1);
		if (!argv[i])
			return 2;
		if (len <= 0 || !WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, argv[i], len, NULL, NULL))
			argv[i][0] = '\0';
	}

	SetConsoleOutputCP(CP_UTF8);

	return run(argc, argv);
}
#else
int main(int argc, char **argv)
{
	return run(argc, argv);
}
#endif
