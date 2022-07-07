/* See LICENSE file for copyright and license details. */
#include "common.h"


void
libsha1_hmac_update(struct libsha1_hmac_state *restrict state, const void *restrict data, size_t n)
{
	if (!state->inited) {
		libsha1_init(&state->sha1_state, state->sha1_state.algorithm);
		libsha1_update(&state->sha1_state, state->ipad, sizeof(state->sha1_state.chunk) * 8);
		state->inited = 1;
	}

	libsha1_update(&state->sha1_state, data, n);
}
