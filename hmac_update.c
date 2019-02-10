/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Feed data into the HMAC algorithm
 * 
 * @param  state  The state of the algorithm
 * @param  data   Data to feed into the algorithm
 * @param  n      The number of bytes to feed into the
 *                algorithm, this must be a multiple of 8
 */
void
libsha1_hmac_update(struct libsha1_hmac_state *restrict state, const void *restrict data, size_t n)
{
	if (!state->inited) {
		libsha1_init(&state->sha1_state, state->sha1_state.algorithm);
		libsha1_update(&state->sha1_state, state->ipad, state->sha1_state.chunk_size * 8);
		state->inited = 1;
	}

	libsha1_update(&state->sha1_state, data, n);
}
