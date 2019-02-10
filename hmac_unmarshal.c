/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Unmarshal an HMAC state from a buffer
 * 
 * @param   state    Output parameter for the unmarshalled state
 * @param   buf      The buffer from which the state shall be unmarshalled
 * @param   bufsize  The maximum number of bytes that can be unmarshalled
 * @return           The number of read bytes, 0 on failure
 */
size_t
libsha1_hmac_unmarshal(struct libsha1_hmac_state *restrict state, const void *restrict buf_, size_t bufsize)
{
	const char *restrict buf = buf_;
	size_t off = 0;
	size_t r;

	if (bufsize < sizeof(int)) {
		errno = EINVAL;
		return 0;
	}

	if (*(const int *)buf) { /* version */
		errno = EINVAL;
		return 0;
	}
	off += sizeof(int);

	r = libsha1_unmarshal(&state->sha1_state, &buf[off], bufsize - off);
	if (!r)
		return 0;
	off += r;

	if (bufsize - off < sizeof(size_t) + sizeof(unsigned char) + 2 * state->sha1_state.chunk_size) {
		errno = EINVAL;
		return 0;
	}

	state->outsize = *(const size_t *)&buf[off];
	off += sizeof(size_t);

	state->inited = *(const unsigned char *)&buf[off];
	off += sizeof(unsigned char);

	memcpy(state->ipad, &buf[off], state->sha1_state.chunk_size);
	off += state->sha1_state.chunk_size;

	memcpy(state->opad, &buf[off], state->sha1_state.chunk_size);
	off += state->sha1_state.chunk_size;

	return off;
}
