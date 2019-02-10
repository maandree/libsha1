/* See LICENSE file for copyright and license details. */
#include "libsha1.h"

#include <sys/stat.h>
#include <alloca.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>


/**
 * Process a chunk using SHA-1 or SHA-0
 * 
 * @param  state  The hashing state
 * @param  chunk  The data to process
 */
#if defined(__GNUC__)
__attribute__((__nonnull__, __nothrow__))
#endif
void libsha1_process(struct libsha1_state *restrict, const unsigned char *restrict);
