/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Get the output size of an algorithm
 * 
 * @param   algorithm  The hashing algorithm
 * @return             The number of bytes in the output, zero on error
 */
size_t
libsha1_algorithm_output_size(enum libsha1_algorithm algorithm)
{
	switch (algorithm) {
	case LIBSHA1_0: return 20;
	case LIBSHA1_1: return 20;
	default:
		errno = EINVAL;
		return 0;
	}
}
