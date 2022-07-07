/* See LICENSE file for copyright and license details. */
#include "common.h"


int
libsha1_hmac_init(struct libsha1_hmac_state *restrict state, enum libsha1_algorithm algorithm,
                  const void *restrict key_, size_t keylen)
{
	const unsigned char *restrict key = key_;
	size_t i;

	state->sha1_state.algorithm = algorithm;
	state->outsize = libsha1_algorithm_output_size(algorithm) * 8;
	if (!state->outsize) {
		errno = EINVAL;
		return -1;
	}
	state->inited = 0;

	if (keylen <= 64 * 8) {
		memset(state->ipad, 0x36, sizeof(state->ipad));
		memset(state->opad, 0x5C, sizeof(state->opad));
		for (i = 0; i < keylen / 8; i++) {
			state->ipad[i] ^= key[i];
			state->opad[i] ^= key[i];
		}
		if (keylen & 7) {
			state->ipad[i] ^= (unsigned char)(key[i] << (8 - (keylen & 7)));
			state->opad[i] ^= (unsigned char)(key[i] << (8 - (keylen & 7)));
		}
	} else {
		memset(state->ipad, 0, sizeof(state->ipad));
		if (libsha1_init(&state->sha1_state, algorithm))
			return -1;
		libsha1_digest(&state->sha1_state, key, keylen, state->ipad);
		memcpy(state->opad, state->ipad, sizeof(state->ipad));
		for (i = 0; i < sizeof(state->ipad); i++) {
			state->ipad[i] ^= 0x36;
			state->opad[i] ^= 0x5C;
		}
	}

	return 0;
}
