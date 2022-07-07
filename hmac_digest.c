/* See LICENSE file for copyright and license details. */
#include "common.h"


void
libsha1_hmac_digest(struct libsha1_hmac_state *restrict state, const void *data, size_t n, void *output)
{
	if (!state->inited) {
		libsha1_init(&state->sha1_state, state->sha1_state.algorithm);
		libsha1_update(&state->sha1_state, state->ipad, sizeof(state->sha1_state.chunk) * 8);
	}

	libsha1_digest(&state->sha1_state, data, n, output);
	libsha1_init(&state->sha1_state, state->sha1_state.algorithm);

	libsha1_update(&state->sha1_state, state->opad, sizeof(state->sha1_state.chunk) * 8);
	libsha1_digest(&state->sha1_state, output, state->outsize, output);
	state->inited = 0;
}
