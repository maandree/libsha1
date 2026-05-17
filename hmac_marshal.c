/* See LICENSE file for copyright and license details. */
#include "common.h"


size_t
libsha1_hmac_marshal(const struct libsha1_hmac_state *restrict state, void *restrict buf_)
{
	unsigned char *restrict buf = buf_;
	size_t off = 0;

	if (buf)
		memcpy(buf, &(int){0}, sizeof(int)); /* version */
	off += sizeof(int);

	off += libsha1_marshal(&state->sha1_state, buf ? &buf[off] : NULL);

	if (buf)
		memcpy(&buf[off], &state->outsize, sizeof(size_t));
	off += sizeof(size_t);

	if (buf)
		buf[off] = state->inited;
	off += sizeof(unsigned char);

	if (buf)
		memcpy(&buf[off], state->ipad, sizeof(state->ipad));
	off += sizeof(state->ipad);

	if (buf)
		memcpy(&buf[off], state->opad, sizeof(state->opad));
	off += sizeof(state->opad);

	return off;
}
