/* See LICENSE file for copyright and license details. */
#include "common.h"


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

	if (bufsize - off < sizeof(size_t) + sizeof(unsigned char) + sizeof(state->ipad) + sizeof(state->opad)) {
		errno = EINVAL;
		return 0;
	}

	state->outsize = *(const size_t *)&buf[off];
	off += sizeof(size_t);

	state->inited = *(const unsigned char *)&buf[off];
	off += sizeof(unsigned char);

	memcpy(state->ipad, &buf[off], sizeof(state->ipad));
	off += sizeof(state->ipad);

	memcpy(state->opad, &buf[off], sizeof(state->opad));
	off += sizeof(state->opad);

	return off;
}
