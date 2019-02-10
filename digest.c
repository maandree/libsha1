/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Absorb the last part of the message and output a hash
 * 
 * @param  state    The hashing state
 * @param  message  The message, in bits
 * @param  msglen   The length of the message, zero if there is nothing more to absorb
 * @param  output   The output buffer for the hash
 */
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

	off = (state->message_size / 8) % state->chunk_size;
	if (msglen) {
		state->chunk[off] = (unsigned char)(*message << (8 - (int)msglen));
		state->chunk[off] |= (unsigned char)(1 << (7 - msglen));
		state->chunk[off] &= (unsigned char)~((1 << (7 - msglen)) - 1);
		state->message_size += msglen;
	} else {
		state->chunk[off] = 0x80;
	}
	off += 1;

	if (off > state->chunk_size - (size_t)8) {
		memset(state->chunk + off, 0, state->chunk_size - off);
		off = 0;
		libsha1_process(state, state->chunk);
	}

	memset(state->chunk + off, 0, state->chunk_size - 8 - off);
	state->chunk[state->chunk_size - 8] = (unsigned char)(state->message_size >> 56);
	state->chunk[state->chunk_size - 7] = (unsigned char)(state->message_size >> 48);
	state->chunk[state->chunk_size - 6] = (unsigned char)(state->message_size >> 40);
	state->chunk[state->chunk_size - 5] = (unsigned char)(state->message_size >> 32);
	state->chunk[state->chunk_size - 4] = (unsigned char)(state->message_size >> 24);
	state->chunk[state->chunk_size - 3] = (unsigned char)(state->message_size >> 16);
	state->chunk[state->chunk_size - 2] = (unsigned char)(state->message_size >>  8);
	state->chunk[state->chunk_size - 1] = (unsigned char)(state->message_size >>  0);
	libsha1_process(state, state->chunk);

	n = libsha1_algorithm_output_size(state->algorithm);
	for (i = 0, n /= 4; i < n; i++) {
		output[4 * i + 0] = (unsigned char)(state->h[i] >> 24);
		output[4 * i + 1] = (unsigned char)(state->h[i] >> 16);
		output[4 * i + 2] = (unsigned char)(state->h[i] >>  8);
		output[4 * i + 3] = (unsigned char)(state->h[i] >>  0);
	}
}
