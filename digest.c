/* See LICENSE file for copyright and license details. */
#include "common.h"


void
libsha1_digest(struct libsha1_state *restrict state, const void *message_, size_t msglen, void *output_)
{
	const char *message = message_;
	unsigned char *output = output_;
	size_t off, i, n;

	if (msglen & ~(size_t)7) {
		libsha1_update(state, message, msglen & ~(size_t)7);
		message += msglen & ~(size_t)7;
		msglen &= (size_t)7;
	}

	off = (state->message_size / 8) % sizeof(state->chunk);
	if (msglen) {
		state->chunk[off] = (unsigned char)(*message << (8 - (int)msglen));
		state->chunk[off] |= (unsigned char)(1 << (7 - msglen));
		state->chunk[off] &= (unsigned char)~((1 << (7 - msglen)) - 1);
		state->message_size += msglen;
	} else {
		state->chunk[off] = 0x80;
	}
	off += 1;

	if (off > sizeof(state->chunk) - (size_t)8) {
		memset(state->chunk + off, 0, sizeof(state->chunk) - off);
		off = 0;
		libsha1_process(state, state->chunk);
	}

	memset(state->chunk + off, 0, sizeof(state->chunk) - 8 - off);
	state->chunk[sizeof(state->chunk) - 8] = (unsigned char)(state->message_size >> 56);
	state->chunk[sizeof(state->chunk) - 7] = (unsigned char)(state->message_size >> 48);
	state->chunk[sizeof(state->chunk) - 6] = (unsigned char)(state->message_size >> 40);
	state->chunk[sizeof(state->chunk) - 5] = (unsigned char)(state->message_size >> 32);
	state->chunk[sizeof(state->chunk) - 4] = (unsigned char)(state->message_size >> 24);
	state->chunk[sizeof(state->chunk) - 3] = (unsigned char)(state->message_size >> 16);
	state->chunk[sizeof(state->chunk) - 2] = (unsigned char)(state->message_size >>  8);
	state->chunk[sizeof(state->chunk) - 1] = (unsigned char)(state->message_size >>  0);
	libsha1_process(state, state->chunk);

	n = libsha1_algorithm_output_size(state->algorithm);
	for (i = 0, n /= 4; i < n; i++) {
		output[4 * i + 0] = (unsigned char)(state->h[i] >> 24);
		output[4 * i + 1] = (unsigned char)(state->h[i] >> 16);
		output[4 * i + 2] = (unsigned char)(state->h[i] >>  8);
		output[4 * i + 3] = (unsigned char)(state->h[i] >>  0);
	}
}
