/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Marshal an HMAC state into a buffer
 * 
 * @param   state  The state to marshal
 * @param   buf    Output buffer, `NULL` to only return the required size
 * @return         The number of bytes marshalled to `buf`
 */
size_t
libsha1_hmac_marshal(const struct libsha1_hmac_state *restrict state, void *restrict buf_)
{
	char *restrict buf = buf_;
	size_t off = 0;

	if (buf)
		*(int *)buf = 0; /* version */
	off += sizeof(int);

	off += libsha1_marshal(&state->sha1_state, buf ? &buf[off] : NULL);

	if (buf)
		*(size_t *)&buf[off] = state->outsize;
	off += sizeof(size_t);

	if (buf)
		*(unsigned char *)&buf[off] = state->inited;
	off += sizeof(unsigned char);

	if (buf)
		memcpy(&buf[off], state->ipad, state->sha1_state.chunk_size);
	off += state->sha1_state.chunk_size;

	if (buf)
		memcpy(&buf[off], state->opad, state->sha1_state.chunk_size);
	off += state->sha1_state.chunk_size;

	return off;
}
