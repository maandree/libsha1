/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Initial state for SHA-0
 */
static const uint32_t H_0[] = {
	0, 0, 0, 0, 0
};

/**
 * Initial state for SHA_1
 */
static const uint32_t H_1[] = {
	0x67452301UL, 0xEFCDAB89UL, 0x98BADCFEUL, 0x10325476UL, 0xC3D2E1F0UL
};


/**
 * Initialise a state
 * 
 * @param   state      The state that should be initialised
 * @param   algorithm  The hashing algorithm
 * @return             Zero on success, -1 on error
 */
int
libsha1_init(struct libsha1_state *restrict state, enum libsha1_algorithm algorithm)
{
	memset(state, 0, sizeof(*state));
	state->message_size = 0;
	state->algorithm = algorithm;

	/* Set initial hash values. */
	switch (algorithm) {
	case LIBSHA1_0: memcpy(state->h, H_0, sizeof(H_0)); break;
	case LIBSHA1_1: memcpy(state->h, H_1, sizeof(H_1)); break;
	default:
		errno = EINVAL;
		return -1;
	}

	state->chunk_size = 64;
  
	return 0;
}
