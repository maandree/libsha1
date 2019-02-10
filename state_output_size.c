/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Get the output size of the algorithm specified for a state
 * 
 * @param   state  The state
 * @return         The number of bytes in the output, zero on error
 */
size_t
libsha1_state_output_size(const struct libsha1_state *restrict state)
{
	return libsha1_algorithm_output_size(state->algorithm);
}
