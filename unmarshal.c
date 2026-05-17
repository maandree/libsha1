/* See LICENSE file for copyright and license details. */
#include "common.h"


size_t
libsha1_unmarshal(struct libsha1_state *restrict state, const void *restrict buf_, size_t bufsize)
{
	const unsigned char *restrict buf = buf_;
	size_t off = 0;
	int version;

	if (bufsize < sizeof(int) + sizeof(enum libsha1_algorithm) + sizeof(size_t)) {
		errno = EINVAL;
		return 0;
	}

	memcpy(&version, buf, sizeof(int));
	if (version < 0 || version > 1) {
		errno = EINVAL;
		return 0;
	}
	off += sizeof(int);

	memcpy(&state->algorithm, &buf[off], sizeof(enum libsha1_algorithm));
	off += sizeof(enum libsha1_algorithm);
	memcpy(&state->message_size, &buf[off], sizeof(size_t));
	off += sizeof(size_t);

	if (bufsize - off < sizeof(state->w) + sizeof(state->h)) {
		errno = EINVAL;
		return 0;
	}
	memset(state->w, 0, sizeof(state->w));
	if (version == 0)
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
