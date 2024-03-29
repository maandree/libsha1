/* See LICENSE file for copyright and license details. */
#include "common.h"


size_t
libsha1_marshal(const struct libsha1_state *restrict state, void *restrict buf_)
{
	char *restrict buf = buf_;
	size_t off = 0;

	if (buf)
		*(int *)buf = 1; /* version */
	off += sizeof(int);
	if (buf)
		*(enum libsha1_algorithm *)&buf[off] = state->algorithm;
	off += sizeof(enum libsha1_algorithm);
	if (buf)
		*(size_t *)&buf[off] = state->message_size;
	off += sizeof(size_t);

	if (buf)
		memcpy(&buf[off], state->h, sizeof(state->h));
	off += sizeof(state->h);

	if (buf)
		memcpy(&buf[off], state->chunk, (state->message_size / 8) % sizeof(state->chunk));
	off += (state->message_size / 8) % sizeof(state->chunk);

	return off;
}
