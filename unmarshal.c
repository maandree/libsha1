/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Unmarshal a state from a buffer
 * 
 * @param   state    Output parameter for the unmarshalled state
 * @param   buf      The buffer from which the state shall be unmarshalled
 * @param   bufsize  The maximum number of bytes that can be unmarshalled
 * @return           The number of read bytes, 0 on failure
 */
size_t
libsha1_unmarshal(struct libsha1_state *restrict state, const void *restrict buf_, size_t bufsize)
{
	const char *restrict buf = buf_;
	size_t off = 0;

	if (bufsize < sizeof(int) + sizeof(enum libsha1_algorithm) + sizeof(size_t)) {
		errno = EINVAL;
		return 0;
	}

	if (*(const int *)buf) { /* version */
		errno = EINVAL;
		return 0;
	}
	off += sizeof(int);

	state->algorithm = *(const enum libsha1_algorithm *)&buf[off];
	off += sizeof(enum libsha1_algorithm);
	state->message_size = *(const size_t *)&buf[off];
	off += sizeof(size_t);

	if (bufsize - off < sizeof(state->w) + sizeof(state->h)) {
		errno = EINVAL;
		return 0;
	}
	memcpy(state->w, &buf[off], sizeof(state->w));
	off += sizeof(state->w);
	memcpy(state->h, &buf[off], sizeof(state->h));
	off += sizeof(state->h);

	if (bufsize - off < (state->message_size / 8) % sizeof(state->chunk)) {
		errno = EINVAL;
		return 0;
	}
	memcpy(state->chunk, &buf[off], (state->message_size / 8) % sizeof(state->chunk));
	off += (state->message_size / 8) % sizeof(state->chunk);

	return off;
}
