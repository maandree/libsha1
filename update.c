/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Absorb more of the message
 * 
 * @param  state    The hashing state
 * @param  message  The message, in bits, must be equivalent to 0 modulus 8
 * @param  msglen   The length of the message
 */
void
libsha1_update(struct libsha1_state *restrict state, const void *restrict message_, size_t msglen)
{
	const char *restrict message = message_;
	size_t n, off;

	off = (state->message_size / 8) % sizeof(state->chunk);
	state->message_size += msglen;
	msglen /= 8;

	if (off) {
		n = msglen < sizeof(state->chunk) - off ? msglen : sizeof(state->chunk) - off;
		memcpy(&state->chunk[off], message, n);
		if (off + n == sizeof(state->chunk))
			libsha1_process(state, state->chunk);
		message += n;
		msglen -= n;
	}

	while (msglen >= sizeof(state->chunk)) {
		libsha1_process(state, (const unsigned char *)message);
		message += sizeof(state->chunk);
		msglen -= sizeof(state->chunk);
	}

	if (msglen)
		memcpy(state->chunk, message, msglen);
}
