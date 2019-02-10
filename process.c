/* See LICENSE file for copyright and license details. */
#include "common.h"


static inline uint32_t
rorl(uint32_t n, int k)
{
	return (n << k) | (n >> (32 - k));
}


/**
 * Process a chunk using SHA-1 or SHA-0
 * 
 * @param  state  The hashing state
 * @param  chunk  The data to process
 */
void
libsha1_process(struct libsha1_state *restrict state, const unsigned char *restrict chunk)
{
#define F0(b, c, d) (d ^ (b & (c ^ d)))
#define F1(b, c, d) (b ^ c ^ d)
#define F2(b, c, d) ((b & c) | (d & (b | c)))
#define F3(b, c, d) (b ^ c ^ d)
#define G0(a, b, c, d, e, i) (e += rorl(a, 5) + F0(b, c, d) + state->w[i] + (uint32_t)0x5A827999UL, b = rorl(b, 30))
#define G1(a, b, c, d, e, i) (e += rorl(a, 5) + F1(b, c, d) + state->w[i] + (uint32_t)0x6ED9EBA1UL, b = rorl(b, 30))
#define G2(a, b, c, d, e, i) (e += rorl(a, 5) + F2(b, c, d) + state->w[i] + (uint32_t)0x8F1BBCDCUL, b = rorl(b, 30))
#define G3(a, b, c, d, e, i) (e += rorl(a, 5) + F3(b, c, d) + state->w[i] + (uint32_t)0xCA62C1D6UL, b = rorl(b, 30))

	uint32_t a, b, c, d, e;
	int i;

	for (i = 0; i < 16; i++) {
		state->w[i]  = (uint32_t)chunk[4 * i + 0] << 24;
		state->w[i] |= (uint32_t)chunk[4 * i + 1] << 16;
		state->w[i] |= (uint32_t)chunk[4 * i + 2] <<  8;
		state->w[i] |= (uint32_t)chunk[4 * i + 3];
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
	state->h[0] += a;
	state->h[1] += b;
	state->h[2] += c;
	state->h[3] += d;
	state->h[4] += e;

#undef F0
#undef F1
#undef F2
#undef F3
#undef G0
#undef G1
#undef G2
#undef G3
}
