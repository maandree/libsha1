/* See LICENSE file for copyright and license details. */
#include "libsha1.h"

#include <sys/stat.h>
#include <alloca.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#ifndef ALLOCA_LIMIT
# define ALLOCA_LIMIT 0
#endif


/**
 * Truncate an unsigned integer to an unsigned 32-bit integer
 * 
 * @param   X:uint_least32_t  The value to truncate
 * @return  :uint_least32_t   The 32 lowest bits in `X`
 */
#define TRUNC32(X) ((X) & (uint_least32_t)0xFFFFFFFFUL)


/**
 * Process a chunk using SHA-1 or SHA-0
 * 
 * @param   state  The hashing state
 * @param   data   The data to process
 * @param   len    The number of available bytes
 * @return         The number of processed bytes
 */
#if defined(__GNUC__)
__attribute__((__nonnull__, __nothrow__))
#endif
size_t libsha1_process(struct libsha1_state *restrict, const unsigned char *restrict, size_t);
