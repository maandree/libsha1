/* See LICENSE file for copyright and license details. */
#ifndef LIBSHA1_H
#define LIBSHA1_H  1

#include <stdint.h>
#include <stddef.h>


/**
 * Algorithms supported by libsha1
 */
enum libsha1_algorithm {
	/**
	 * SHA-0, outputs 20 bytes
	 */
	LIBSHA1_0,

	/**
	 * SHA-1, outputs 20 bytes
	 */
	LIBSHA1_1
};

/**
 * Data structure that describes the state of a hashing process
 * 
 * Data that could just as well be allocated (with `auto`) are
 * allocated here so that is is easier to wipe the data without
 * exposing two versions of each function: one to wipe data,
 * and one not to wipe data to gain speed, now you can use use
 * `explicit_bzero` (or `memset`) when you are done.
 */
struct libsha1_state {
	/**
	 * The size of the message, as far as processed, in bits;
	 */
	size_t message_size;

	/**
	 * Words
	 * 
	 * Does not need to be marshalled
	 */
	uint32_t w[80];

	/**
	 * Hashing values
	 */
	uint32_t h[5];

	/**
	 * Space for chunks to process
	 */
	unsigned char chunk[64];

	/**
	 * The algorithm that is used
	 */
	enum libsha1_algorithm algorithm;

	int __padding1;
};


/**
 * Data structure that describes the state of a HMAC hashing process
 * 
 * Data that could just as well be allocated (with `auto`) are
 * allocated here so that is is easier to wipe the data without
 * exposing two versions of each function: one to wipe data,
 * and one not to wipe data to gain speed, now you can use use
 * `explicit_bzero` (or `memset`) when you are done.
 */
struct libsha1_hmac_state {
	/**
	 * State of the underlaying hash function
	 */
	struct libsha1_state sha1_state;

	/**
	 * The output size of the underlaying
	 * hash algorithm, in bits
	 */
	size_t outsize;

	/**
	 * Whether `.sha1_state` has been initialised
	 * and whether the `ipad` has been feed into
	 * the algorithm
	 */
	unsigned char inited;

	/**
	 * Inner pad XOR processed key
	 */
	unsigned char ipad[64];

	/**
	 * Outer pad XOR processed key
	 */
	unsigned char opad[64];
};


/**
 * Initialise a state
 * 
 * @param   state      The state that should be initialised
 * @param   algorithm  The hashing algorithm
 * @return             Zero on success, -1 on error
 */
#if defined(__GNUC__)
__attribute__((__leaf__, __nothrow__, __nonnull__))
#endif
int libsha1_init(struct libsha1_state *restrict, enum libsha1_algorithm);

/**
 * Get the output size of the algorithm specified for a state
 * 
 * @param   state  The state
 * @return         The number of bytes in the output, zero on error
 */
#if defined(__GNUC__)
__attribute__((__nothrow__, __nonnull__, __pure__))
#endif
size_t libsha1_state_output_size(const struct libsha1_state *restrict);

/**
 * Get the output size of an algorithm
 * 
 * @param   algorithm  The hashing algorithm
 * @return             The number of bytes in the output, zero on error
 */
#if defined(__GNUC__)
__attribute__((__leaf__, __nothrow__, __const__))
#endif
size_t libsha1_algorithm_output_size(enum libsha1_algorithm);

/**
 * Absorb more of the message
 * 
 * @param  state    The hashing state
 * @param  message  The message, in bits, must be equivalent to 0 modulus 8
 * @param  msglen   The length of the message
 */
#if defined(__GNUC__)
__attribute__((__nonnull__, __nothrow__))
#endif
void libsha1_update(struct libsha1_state *restrict, const void *restrict, size_t);

/**
 * Absorb the last part of the message and output a hash
 * 
 * @param  state    The hashing state
 * @param  message  The message, in bits
 * @param  msglen   The length of the message, zero if there is nothing more to absorb
 * @param  output   The output buffer for the hash
 */
#if defined(__GNUC__)
__attribute__((__nonnull__(1, 4), __nothrow__))
#endif
void libsha1_digest(struct libsha1_state *restrict, const void *, size_t, void *);

/**
 * Calculate the checksum for a file,
 * the content of the file is assumed non-sensitive
 * 
 * @param   fd         The file descriptor of the file
 * @param   algorithm  The hashing algorithm
 * @param   hashsum    Output buffer for the hash
 * @return             Zero on success, -1 on error
 */
#if defined(__GNUC__)
__attribute__((__nonnull__, __leaf__))
#endif
int libsha1_sum_fd(int, enum libsha1_algorithm, void *restrict);

/**
 * Convert a binary hashsum to lower case hexadecimal representation
 * 
 * @param  output   Output array, should have an allocation size of at least `2 * n + 1`
 * @param  hashsum  The hashsum to convert
 * @param  n        The size of `hashsum`
 */
#if defined(__GNUC__)
__attribute__((__leaf__, __nonnull__, __nothrow__))
#endif
void libsha1_behex_lower(char *restrict, const void *restrict, size_t);

/**
 * Convert a binary hashsum to upper case hexadecimal representation
 * 
 * @param  output   Output array, should have an allocation size of at least `2 * n + 1`
 * @param  hashsum  The hashsum to convert
 * @param  n        The size of `hashsum`
 */
#if defined(__GNUC__)
__attribute__((__leaf__, __nonnull__, __nothrow__))
#endif
void libsha1_behex_upper(char *restrict, const void *restrict, size_t);

/**
 * Convert a hexadecimal hashsum (both lower case, upper
 * case and mixed is supported) to binary representation
 * 
 * @param  output   Output array, should have an allocation
 *                  size of at least `strlen(hashsum) / 2`
 * @param  hashsum  The hashsum to convert
 */
#if defined(__GNUC__)
__attribute__((__leaf__, __nonnull__, __nothrow__))
#endif
void libsha1_unhex(void *restrict, const char *restrict);

/**
 * Marshal a state into a buffer
 * 
 * @param   state  The state to marshal
 * @param   buf    Output buffer, `NULL` to only return the required size
 * @return         The number of bytes marshalled to `buf`
 */
#if defined(__GNUC__)
__attribute__((__leaf__, __nonnull__(1), __nothrow__))
#endif
size_t libsha1_marshal(const struct libsha1_state *restrict, void *restrict);

/**
 * Unmarshal a state from a buffer
 * 
 * @param   state    Output parameter for the unmarshalled state
 * @param   buf      The buffer from which the state shall be unmarshalled
 * @param   bufsize  The maximum number of bytes that can be unmarshalled
 * @return           The number of read bytes, 0 on failure
 */
#if defined(__GNUC__)
__attribute__((__leaf__, __nonnull__, __nothrow__))
#endif
size_t libsha1_unmarshal(struct libsha1_state *restrict, const void *restrict, size_t);

/**
 * Initialise an HMAC state
 * 
 * @param   state        The state that should be initialised
 * @param   algorithm    The hashing algorithm
 * @param   key          The key
 * @param   key_length   The length of key, in bits
 * @return               Zero on success, -1 on error
 */
#if defined(__GNUC__)
__attribute__((__leaf__, __nonnull__, __nothrow__))
#endif
int libsha1_hmac_init(struct libsha1_hmac_state *restrict, enum libsha1_algorithm, const void *restrict, size_t);

/**
 * Get the output size of the algorithm specified for an HMAC state
 * 
 * @param   state  The state
 * @return         The number of bytes in the output, zero on error
 */
#if defined(__GNUC__)
__attribute__((__nothrow__, __nonnull__, __pure__))
#endif
size_t libsha1_hmac_state_output_size(const struct libsha1_hmac_state *restrict);

/**
 * Feed data into the HMAC algorithm
 * 
 * @param  state  The state of the algorithm
 * @param  data   Data to feed into the algorithm
 * @param  n      The number of bytes to feed into the
 *                algorithm, this must be a multiple of 8
 */
#if defined(__GNUC__)
__attribute__((__leaf__, __nonnull__, __nothrow__))
#endif
void libsha1_hmac_update(struct libsha1_hmac_state *restrict, const void *restrict, size_t);

/**
 * Feed data into the HMAC algorithm and
 * get the result
 * 
 * The state of the algorithm will be reset and
 * `libsha1_hmac_update` and `libsha1_hmac_update`
 * can be called again
 * 
 * @param  state   The state of the algorithm
 * @param  data    Data to feed into the algorithm
 * @param  n       The number of bytes to feed into the algorithm
 * @param  output  The output buffer for the hash, it will be as
 *                 large as for the underlaying hash algorithm
 */
#if defined(__GNUC__)
__attribute__((__leaf__, __nonnull__, __nothrow__))
#endif
void libsha1_hmac_digest(struct libsha1_hmac_state *restrict, const void *, size_t, void *);

/**
 * Marshal an HMAC state into a buffer
 * 
 * @param   state  The state to marshal
 * @param   buf    Output buffer, `NULL` to only return the required size
 * @return         The number of bytes marshalled to `buf`
 */
#if defined(__GNUC__)
__attribute__((__leaf__, __nonnull__(1), __nothrow__))
#endif
size_t libsha1_hmac_marshal(const struct libsha1_hmac_state *restrict, void *restrict);

/**
 * Unmarshal an HMAC state from a buffer
 * 
 * @param   state    Output parameter for the unmarshalled state
 * @param   buf      The buffer from which the state shall be unmarshalled
 * @param   bufsize  The maximum number of bytes that can be unmarshalled
 * @return           The number of read bytes, 0 on failure
 */
#if defined(__GNUC__)
__attribute__((__leaf__, __nonnull__, __nothrow__))
#endif
size_t libsha1_hmac_unmarshal(struct libsha1_hmac_state *restrict, const void *restrict, size_t);


#endif
