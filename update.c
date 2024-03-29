/* See LICENSE file for copyright and license details. */
#include "common.h"


void
libsha1_update(struct libsha1_state *restrict state, const void *restrict message_, size_t msglen)
{
	const unsigned char *restrict message = message_;
	size_t n, off;

	off = (state->message_size / 8) % sizeof(state->chunk);
	state->message_size += msglen;
	msglen /= 8;

	if (off) {
		n = msglen < sizeof(state->chunk) - off ? msglen : sizeof(state->chunk) - off;
		memcpy(&state->chunk[off], message, n);
		if (off + n == sizeof(state->chunk))
			libsha1_process(state, state->chunk, sizeof(state->chunk));
		message += n;
		msglen -= n;
	}

	off = libsha1_process(state, message, msglen);

	if (msglen > off)
		memcpy(state->chunk, &message[off], msglen - off);
}
