/* See LICENSE file for copyright and license details. */
#include "common.h"


static inline uint_least32_t
rorl(uint_least32_t n, int k)
{
	return TRUNC32((n << k) | (n >> (32 - k)));
}


void
libsha1_process(struct libsha1_state *restrict state, const unsigned char *restrict chunk)
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
	int i;

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
