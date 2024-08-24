/* See LICENSE file for copyright and license details. */
#include "common.h"
#include <stdatomic.h>

#if defined(__SSE4_1__) && defined(__SSSE3__) && defined(__SSE2__) && defined(__SHA__)
# define HAVE_X86_SHA_INTRINSICS
#endif


#ifdef HAVE_X86_SHA_INTRINSICS
# include <immintrin.h>
#endif


static inline uint_least32_t
rorl(uint_least32_t n, int k)
{
	return TRUNC32((n << k) | (n >> (32 - k)));
}

static size_t
process_portable(struct libsha1_state *restrict state, const unsigned char *restrict data, size_t len)
{
#define F0(B, C, D) (D ^ (B & (C ^ D)))
#define F1(B, C, D) (B ^ C ^ D)
#define F2(B, C, D) ((B & C) | (D & (B | C)))
#define F3(B, C, D) (B ^ C ^ D)
#define G_(A, B, C, D, E, I, F, X) (E = TRUNC32(E + rorl(A, 5) + F(B, C, D) + state->w[I] + (uint_least32_t)X##UL), B = rorl(B, 30))
#define G0(A, B, C, D, E, I) G_(A, B, C, D, E, I, F0, 0x5A827999)
#define G1(A, B, C, D, E, I) G_(A, B, C, D, E, I, F1, 0x6ED9EBA1)
#define G2(A, B, C, D, E, I) G_(A, B, C, D, E, I, F2, 0x8F1BBCDC)
#define G3(A, B, C, D, E, I) G_(A, B, C, D, E, I, F3, 0xCA62C1D6)

	uint_least32_t a, b, c, d, e;
	const unsigned char *restrict chunk;
	int i;
	size_t off = 0;

	for (; len >= off + sizeof(state->chunk); off += sizeof(state->chunk)) {
		chunk = &data[off];
		for (i = 0; i < 16; i++) {
			state->w[i]  = (uint_least32_t)chunk[4 * i + 0] << 24;
			state->w[i] |= (uint_least32_t)chunk[4 * i + 1] << 16;
			state->w[i] |= (uint_least32_t)chunk[4 * i + 2] <<  8;
			state->w[i] |= (uint_least32_t)chunk[4 * i + 3];
		}
		if (state->algorithm == LIBSHA1_1) {
			for (; i < 80; i++)
				state->w[i] = rorl(state->w[i - 3] ^ state->w[i - 8] ^ state->w[i - 14] ^ state->w[i - 16], 1);
		} else {
			for (; i < 80; i++)
				state->w[i] = state->w[i - 3] ^ state->w[i - 8] ^ state->w[i - 14] ^ state->w[i - 16];
		}

		a = state->h[0];
		b = state->h[1];
		c = state->h[2];
		d = state->h[3];
		e = state->h[4];

		for (i = 0; i < 20;) {
			G0(a, b, c, d, e, i++);
			G0(e, a, b, c, d, i++);
			G0(d, e, a, b, c, i++);
			G0(c, d, e, a, b, i++);
			G0(b, c, d, e, a, i++);
		}
		while (i < 40) {
			G1(a, b, c, d, e, i++);
			G1(e, a, b, c, d, i++);
			G1(d, e, a, b, c, i++);
			G1(c, d, e, a, b, i++);
			G1(b, c, d, e, a, i++);
		}
		while (i < 60) {
			G2(a, b, c, d, e, i++);
			G2(e, a, b, c, d, i++);
			G2(d, e, a, b, c, i++);
			G2(c, d, e, a, b, i++);
			G2(b, c, d, e, a, i++);
		}
		while (i < 80) {
			G3(a, b, c, d, e, i++);
			G3(e, a, b, c, d, i++);
			G3(d, e, a, b, c, i++);
			G3(c, d, e, a, b, i++);
			G3(b, c, d, e, a, i++);
		}

		state->h[0] = TRUNC32(state->h[0] + a);
		state->h[1] = TRUNC32(state->h[1] + b);
		state->h[2] = TRUNC32(state->h[2] + c);
		state->h[3] = TRUNC32(state->h[3] + d);
		state->h[4] = TRUNC32(state->h[4] + e);
	}

	return off;

#undef F0
#undef F1
#undef F2
#undef F3
#undef G_
#undef G0
#undef G1
#undef G2
#undef G3
}

#ifdef HAVE_X86_SHA_INTRINSICS

static size_t
process_x86_sha(struct libsha1_state *restrict state, const unsigned char *restrict data, size_t len)
{
	const __m128i SHUFFLE_MASK = _mm_set_epi64x(0x0001020304050607ULL, 0x08090A0B0C0D0E0FULL);
	register __m128i abcd, e000, temp, msg0, msg1, msg2, msg3;
	__m128i abcd_orig, e000_orig;
	size_t off = 0;

	abcd_orig = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i *)&state->h[0]), 32 - 5);
	e000_orig = _mm_set_epi32((int)state->h[4], 0, 0, 0);

	for (; len >= off + sizeof(state->chunk); off += sizeof(state->chunk)) {
		msg0 = _mm_loadu_si128((const __m128i *)&data[0]);
		msg0 = _mm_shuffle_epi8(msg0, SHUFFLE_MASK);
		e000 = _mm_add_epi32(e000_orig, msg0);
		temp = abcd_orig;
		abcd = _mm_sha1rnds4_epu32(abcd_orig, e000, 0);

		msg1 = _mm_loadu_si128((const __m128i *)&data[16]);
		msg1 = _mm_shuffle_epi8(msg1, SHUFFLE_MASK);
		temp = _mm_sha1nexte_epu32(temp, msg1);
		e000 = abcd;
		abcd = _mm_sha1rnds4_epu32(abcd, temp, 0);
		msg0 = _mm_sha1msg1_epu32(msg0, msg1);

		msg2 = _mm_loadu_si128((const __m128i *)&data[32]);
		msg2 = _mm_shuffle_epi8(msg2, SHUFFLE_MASK);
		e000 = _mm_sha1nexte_epu32(e000, msg2);
		temp = abcd;
		abcd = _mm_sha1rnds4_epu32(abcd, e000, 0);
		msg1 = _mm_sha1msg1_epu32(msg1, msg2);
		msg0 = _mm_xor_si128(msg0, msg2);

		msg3 = _mm_loadu_si128((const __m128i *)&data[48]);
		msg3 = _mm_shuffle_epi8(msg3, SHUFFLE_MASK);
		temp = _mm_sha1nexte_epu32(temp, msg3);
		e000 = abcd;
		msg0 = _mm_sha1msg2_epu32(msg0, msg3);
		abcd = _mm_sha1rnds4_epu32(abcd, temp, 0);
		msg2 = _mm_sha1msg1_epu32(msg2, msg3);
		msg1 = _mm_xor_si128(msg1, msg3);

		e000 = _mm_sha1nexte_epu32(e000, msg0);
		temp = abcd;
		msg1 = _mm_sha1msg2_epu32(msg1, msg0);
		abcd = _mm_sha1rnds4_epu32(abcd, e000, 0);
		msg3 = _mm_sha1msg1_epu32(msg3, msg0);
		msg2 = _mm_xor_si128(msg2, msg0);

		temp = _mm_sha1nexte_epu32(temp, msg1);
		e000 = abcd;
		msg2 = _mm_sha1msg2_epu32(msg2, msg1);
		abcd = _mm_sha1rnds4_epu32(abcd, temp, 1);
		msg0 = _mm_sha1msg1_epu32(msg0, msg1);
		msg3 = _mm_xor_si128(msg3, msg1);

		e000 = _mm_sha1nexte_epu32(e000, msg2);
		temp = abcd;
		msg3 = _mm_sha1msg2_epu32(msg3, msg2);
		abcd = _mm_sha1rnds4_epu32(abcd, e000, 1);
		msg1 = _mm_sha1msg1_epu32(msg1, msg2);
		msg0 = _mm_xor_si128(msg0, msg2);

		temp = _mm_sha1nexte_epu32(temp, msg3);
		e000 = abcd;
		msg0 = _mm_sha1msg2_epu32(msg0, msg3);
		abcd = _mm_sha1rnds4_epu32(abcd, temp, 1);
		msg2 = _mm_sha1msg1_epu32(msg2, msg3);
		msg1 = _mm_xor_si128(msg1, msg3);

		e000 = _mm_sha1nexte_epu32(e000, msg0);
		temp = abcd;
		msg1 = _mm_sha1msg2_epu32(msg1, msg0);
		abcd = _mm_sha1rnds4_epu32(abcd, e000, 1);
		msg3 = _mm_sha1msg1_epu32(msg3, msg0);
		msg2 = _mm_xor_si128(msg2, msg0);

		temp = _mm_sha1nexte_epu32(temp, msg1);
		e000 = abcd;
		msg2 = _mm_sha1msg2_epu32(msg2, msg1);
		abcd = _mm_sha1rnds4_epu32(abcd, temp, 1);
		msg0 = _mm_sha1msg1_epu32(msg0, msg1);
		msg3 = _mm_xor_si128(msg3, msg1);

		e000 = _mm_sha1nexte_epu32(e000, msg2);
		temp = abcd;
		msg3 = _mm_sha1msg2_epu32(msg3, msg2);
		abcd = _mm_sha1rnds4_epu32(abcd, e000, 2);
		msg1 = _mm_sha1msg1_epu32(msg1, msg2);
		msg0 = _mm_xor_si128(msg0, msg2);

		temp = _mm_sha1nexte_epu32(temp, msg3);
		e000 = abcd;
		msg0 = _mm_sha1msg2_epu32(msg0, msg3);
		abcd = _mm_sha1rnds4_epu32(abcd, temp, 2);
		msg2 = _mm_sha1msg1_epu32(msg2, msg3);
		msg1 = _mm_xor_si128(msg1, msg3);

		e000 = _mm_sha1nexte_epu32(e000, msg0);
		temp = abcd;
		msg1 = _mm_sha1msg2_epu32(msg1, msg0);
		abcd = _mm_sha1rnds4_epu32(abcd, e000, 2);
		msg3 = _mm_sha1msg1_epu32(msg3, msg0);
		msg2 = _mm_xor_si128(msg2, msg0);

		temp = _mm_sha1nexte_epu32(temp, msg1);
		e000 = abcd;
		msg2 = _mm_sha1msg2_epu32(msg2, msg1);
		abcd = _mm_sha1rnds4_epu32(abcd, temp, 2);
		msg0 = _mm_sha1msg1_epu32(msg0, msg1);
		msg3 = _mm_xor_si128(msg3, msg1);

		e000 = _mm_sha1nexte_epu32(e000, msg2);
		temp = abcd;
		msg3 = _mm_sha1msg2_epu32(msg3, msg2);
		abcd = _mm_sha1rnds4_epu32(abcd, e000, 2);
		msg1 = _mm_sha1msg1_epu32(msg1, msg2);
		msg0 = _mm_xor_si128(msg0, msg2);

		temp = _mm_sha1nexte_epu32(temp, msg3);
		e000 = abcd;
		msg0 = _mm_sha1msg2_epu32(msg0, msg3);
		abcd = _mm_sha1rnds4_epu32(abcd, temp, 3);
		msg2 = _mm_sha1msg1_epu32(msg2, msg3);
		msg1 = _mm_xor_si128(msg1, msg3);

		e000 = _mm_sha1nexte_epu32(e000, msg0);
		temp = abcd;
		msg1 = _mm_sha1msg2_epu32(msg1, msg0);
		abcd = _mm_sha1rnds4_epu32(abcd, e000, 3);
		msg3 = _mm_sha1msg1_epu32(msg3, msg0);
		msg2 = _mm_xor_si128(msg2, msg0);

		temp = _mm_sha1nexte_epu32(temp, msg1);
		e000 = abcd;
		msg2 = _mm_sha1msg2_epu32(msg2, msg1);
		abcd = _mm_sha1rnds4_epu32(abcd, temp, 3);
		msg3 = _mm_xor_si128(msg3, msg1);

		e000 = _mm_sha1nexte_epu32(e000, msg2);
		temp = abcd;
		msg3 = _mm_sha1msg2_epu32(msg3, msg2);
		abcd = _mm_sha1rnds4_epu32(abcd, e000, 3);

		temp = _mm_sha1nexte_epu32(temp, msg3);
		e000 = abcd;
		abcd = _mm_sha1rnds4_epu32(abcd, temp, 3);

		e000_orig = _mm_sha1nexte_epu32(e000, e000_orig);
		abcd_orig = _mm_add_epi32(abcd, abcd_orig);
	}

	_mm_storeu_si128((__m128i *)&state->h[0], _mm_shuffle_epi32(abcd_orig, 32 - 5));
	state->h[4] = (uint_least32_t)_mm_extract_epi32(e000_orig, 3);

	return off;
}

# if defined(__GNUC__)
__attribute__((__constructor__))
# endif
static int
have_sha_intrinsics(void)
{
        static volatile int ret = -1;
        static volatile atomic_flag spinlock = ATOMIC_FLAG_INIT;
	int a, b, c, d;

	if (ret != -1)
		return ret;

        while (atomic_flag_test_and_set(&spinlock));

	if (ret != -1)
		goto out;

	a = 7;
	c = 0;
	__asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(a), "c"(c));
	if (!(b & (1 << 29))) {
		ret = 0;
		goto out;
	}
	a = 1;
	__asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(a), "c"(c));
	if (!(c & (1 << 19)) || !(c & (1 << 0)) || !(d & (1 << 26))) {
		ret = 0;
		goto out;
	}
	ret = 1;

out:
	atomic_flag_clear(&spinlock);
	return ret;
}

#endif

size_t
libsha1_process(struct libsha1_state *restrict state, const unsigned char *restrict data, size_t len)
{
#ifdef HAVE_X86_SHA_INTRINSICS
	if (state->algorithm == LIBSHA1_1 && have_sha_intrinsics())
		return process_x86_sha(state, data, len);
#endif
	return process_portable(state, data, len);
}
