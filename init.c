/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Initial state for SHA-1 and SHA-0
 */
static const uint32_t H[] = {
	0x67452301UL, 0xEFCDAB89UL, 0x98BADCFEUL, 0x10325476UL, 0xC3D2E1F0UL
};


int
libsha1_init(struct libsha1_state *restrict state, enum libsha1_algorithm algorithm)
{
	memset(state, 0, sizeof(*state));
	state->message_size = 0;
	state->algorithm = algorithm;

	/* Set initial hash values. */
	switch (algorithm) {
	case LIBSHA1_0:
	case LIBSHA1_1:
		memcpy(state->h, H, sizeof(H));
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	return 0;
}
