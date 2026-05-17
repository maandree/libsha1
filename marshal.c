/* See LICENSE file for copyright and license details. */
#include "common.h"


size_t
libsha1_marshal(const struct libsha1_state *restrict state, void *restrict buf_)
{
	unsigned char *restrict buf = buf_;
	size_t off = 0;

	if (buf)
		memcpy(buf, &(int){1}, sizeof(int));
	off += sizeof(int);
	if (buf)
		memcpy(&buf[off], &state->algorithm, sizeof(enum libsha1_algorithm));
	off += sizeof(enum libsha1_algorithm);
	if (buf)
		memcpy(&buf[off], &state->message_size, sizeof(size_t));
	off += sizeof(size_t);

	if (buf)
		memcpy(&buf[off], state->h, sizeof(state->h));
	off += sizeof(state->h);

	if (buf)
		memcpy(&buf[off], state->chunk, (state->message_size / 8) % sizeof(state->chunk));
	off += (state->message_size / 8) % sizeof(state->chunk);

	return off;
}
