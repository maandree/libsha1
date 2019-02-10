/* See LICENSE file for copyright and license details. */
#include "libsha1.h"

#include <sys/wait.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define test(EXPR)\
	do {\
		if (EXPR)\
			break;\
		fprintf(stderr, "Failure at line %i: %s\n", __LINE__, #EXPR);\
		exit(1);\
	} while (0)

#define test_str(HAVE, EXPECTED)\
	do {\
		if (!strcmp(HAVE, EXPECTED))\
			break;\
		fprintf(stderr, "Failure at line %i: expected \"%s\", got \"%s\"\n", __LINE__, EXPECTED, HAVE);\
		exit(1);\
	} while (0)

#define test_repeated(CHR, N, ALGO, EXPECTED)\
	do {\
		memset(buf, CHR, N);\
		test(!libsha1_init(&s, ALGO));\
		libsha1_digest(&s, buf, (N) * 8, buf);\
		libsha1_behex_lower(str, buf, libsha1_state_output_size(&s));\
		test_str(str, EXPECTED);\
	} while (0)

#define test_repeated_huge(CHR, N, ALGO, EXPECTED)\
	do {\
		size_t n__ = N;\
		if (skip_huge)\
			break;\
		memset(buf, CHR, sizeof(buf));\
		test(!libsha1_init(&s, ALGO));\
		fprintf(stderr, "processing huge message: 0 %%\n");\
		for (; n__ > sizeof(buf); n__ -= sizeof(buf)) {\
			libsha1_update(&s, buf, sizeof(buf) * 8);\
			fprintf(stderr, "\033[A\033[Kprocessing huge message: %zu %%\n", ((N) - n__) * 100 / (N));\
		}\
		libsha1_update(&s, buf, n__ * 8);\
		fprintf(stderr, "\033[A\033[K");\
		fflush(stderr);\
		libsha1_digest(&s, NULL, 0, buf);\
		libsha1_behex_lower(str, buf, libsha1_state_output_size(&s));\
		test_str(str, EXPECTED);\
	} while (0)

#define test_custom(S, ALGO, EXPECTED)\
	do {\
		test(!libsha1_init(&s, ALGO));\
		libsha1_digest(&s, S, (sizeof(S) - 1) * 8, buf);\
		libsha1_behex_lower(str, buf, libsha1_state_output_size(&s));\
		test_str(str, EXPECTED);\
	} while (0)

#define test_bits(S, N, ALGO, EXPECTED)\
	do {\
		libsha1_unhex(buf, S);\
		test(!libsha1_init(&s, ALGO));\
		libsha1_digest(&s, buf, N, buf);\
		libsha1_behex_lower(str, buf, libsha1_state_output_size(&s));\
		test_str(str, EXPECTED);\
	} while (0)

#define test_hmac(ALGO, TEXT, KEY, MAC)\
	do {\
		libsha1_unhex(buf, KEY);\
		test(!libsha1_hmac_init(&hs, ALGO, buf, (sizeof(KEY) - 1) << 2));\
		libsha1_unhex(buf, TEXT);\
		libsha1_hmac_digest(&hs, buf, (sizeof(TEXT) - 1) << 2, buf);\
		libsha1_behex_lower(str, buf, libsha1_hmac_state_output_size(&hs));\
		test_str(str, MAC);\
	} while (0)


int
main(int argc, char *argv[])
{
	char buf[8096], str[2048];
	struct libsha1_state s;
	struct libsha1_hmac_state hs;
	int skip_huge, fds[2], status;
	size_t i, j, n, len;
	ssize_t r;
	pid_t pid;

	skip_huge = (argc == 2 && !strcmp(argv[1], "skip-huge"));

	libsha1_behex_lower(buf, "", 0);
	test_str(buf, "");

	libsha1_behex_lower(buf, "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF", 16);
	test_str(buf, "00112233445566778899aabbccddeeff");

	libsha1_behex_lower(buf, "\x1E\x5A\xC0", 3);
	test_str(buf, "1e5ac0");

	libsha1_behex_upper(buf, "", 0);
	test_str(buf, "");

	libsha1_behex_upper(buf, "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF", 16);
	test_str(buf, "00112233445566778899AABBCCDDEEFF");

	libsha1_behex_upper(buf, "\x1E\x5A\xC0", 3);
	test_str(buf, "1E5AC0");

	libsha1_unhex(buf, "");
	test(!memcmp(buf, "", 0));

	libsha1_unhex(buf, "00112233445566778899AABBCCDDEEFF");
	test(!memcmp(buf, "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF", 16));

	libsha1_unhex(buf, "1E5AC0");
	test(!memcmp(buf, "\x1E\x5A\xC0", 3));

	libsha1_unhex(buf, "00112233445566778899aabbccddeeff");
	test(!memcmp(buf, "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF", 16));

	libsha1_unhex(buf, "1e5ac0");
	test(!memcmp(buf, "\x1E\x5A\xC0", 3));

	libsha1_unhex(buf, "AAbbCcdD");
	test(!memcmp(buf, "\xAA\xBB\xCC\xDD", 4));

	test(libsha1_algorithm_output_size(LIBSHA1_0) == 20);
	test(libsha1_algorithm_output_size(LIBSHA1_1) == 20);
	test(!errno);
	test(libsha1_algorithm_output_size(~0) == 0); /* should test `errno == EINVAL`, optimising compiler breaks it */

	errno = 0;
	test(libsha1_init(&s, ~0) == -1 && errno == EINVAL);
	errno = 0;

	test(!libsha1_init(&s, LIBSHA1_1));
	test(libsha1_state_output_size(&s) == 20);
	libsha1_digest(&s, "", 0, buf);
	libsha1_behex_lower(str, buf, libsha1_state_output_size(&s));
	test_str(str, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

	test_custom("abc", LIBSHA1_0, "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880");

	test_repeated(0xFF, 1, LIBSHA1_1, "85e53271e14006f0265921d02d4d736cdc580b0b");
	test_custom("\xE5\xE0\x99\x24", LIBSHA1_1, "d1dffbc8a175dd8eebe0da87b1792b6dc1018e82");
	test_repeated(0x00, 56, LIBSHA1_1, "9438e360f578e12c0e0e8ed28e2c125c1cefee16");
	test_repeated(0x51, 1000, LIBSHA1_1, "49f1cfe3829963158e2b2b2cb5df086cee2e3bb0");
	test_repeated(0x41, 1000, LIBSHA1_1, "3ae3644d6777a1f56a1defeabc74af9c4b313e49");
	test_repeated(0x99, 1005, LIBSHA1_1, "18685d56c8bf67c3cee4443e9a78f65c30752f5d");
	test_repeated_huge(0x00, 1000000UL, LIBSHA1_1, "bef3595266a65a2ff36b700a75e8ed95c68210b6");
	test_repeated_huge(0x41, 0x20000000UL, LIBSHA1_1, "df3f26fce8fa7bec2c61d0506749a320ac7dc942");
	test_repeated_huge(0x00, 0x41000000UL, LIBSHA1_1, "320c617b0b6ee1b6f9c3271eae135f40cae22c10");
	test_repeated_huge(0x84, 0x6000003FUL, LIBSHA1_1, "b20aa99b62e6a480fd93b4d24b2c19ffac649bb8");
	test_custom("abc", LIBSHA1_1, "a9993e364706816aba3e25717850c26c9cd0d89d");
	test_custom("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", LIBSHA1_1,
	            "84983e441c3bd26ebaae4aa1f95129e5e54670f1");

	for (i = 0; i < 1000; i++) {
		for (j = 1; j < 2; j++) {
			memset(buf, 0x41, 1000);
			test(!libsha1_init(&s, (enum libsha1_algorithm)j));
			libsha1_update(&s, buf, i * 8);
			libsha1_digest(&s, buf, (1000 - i) * 8, buf);
			libsha1_behex_lower(str, buf, libsha1_state_output_size(&s));
			test_str(str, "3ae3644d6777a1f56a1defeabc74af9c4b313e49");

			memset(buf, 0x41, 1000);
			test(!libsha1_init(&s, (enum libsha1_algorithm)j));
			libsha1_update(&s, buf, i * 8);
			libsha1_update(&s, buf, (1000 - i) * 8);
			libsha1_digest(&s, NULL, 0, buf);
			libsha1_behex_lower(str, buf, libsha1_state_output_size(&s));
			test_str(str, "3ae3644d6777a1f56a1defeabc74af9c4b313e49");

			if (!i)
				continue;

			memset(buf, 0x41, 1000);
			test(!libsha1_init(&s, (enum libsha1_algorithm)j));
			for (n = 0; n + i < 1000; n += i) {
				libsha1_update(&s, buf, i * 8);
				test((len = libsha1_marshal(&s, NULL)) && len <= sizeof(str));
				test(libsha1_marshal(&s, str) == len);
				memset(&s, 0, sizeof(s));
				test(libsha1_unmarshal(&s, str, sizeof(str)) == len);
			}
			libsha1_digest(&s, buf, (1000 - n) * 8, buf);
			libsha1_behex_lower(str, buf, libsha1_state_output_size(&s));
			test_str(str, "3ae3644d6777a1f56a1defeabc74af9c4b313e49");
		}
	}

	test(!errno);

	test(!pipe(fds));
	test((pid = fork()) >= 0);
	if (!pid) {
		close(fds[0]);
		memset(buf, 0x41, 1000);
		for (n = 1000; n; n -= (size_t)r)
			test((r = write(fds[1], buf, n < 8 ? n : 8)) > 0);
		exit(0);
	}
	close(fds[1]);
	test(!libsha1_sum_fd(fds[0], LIBSHA1_1, buf));
	test(waitpid(pid, &status, 0) == pid);
	test(!status);
	close(fds[0]);
	libsha1_behex_lower(str, buf, libsha1_algorithm_output_size(LIBSHA1_1));
	test_str(str, "3ae3644d6777a1f56a1defeabc74af9c4b313e49");

	test_bits("00", 1, LIBSHA1_1, "bb6b3e18f0115b57925241676f5b1ae88747b08a");
	test_bits("01", 2, LIBSHA1_1, "ec6b39952e1a3ec3ab3507185cf756181c84bbe2");
	test_bits("04", 3, LIBSHA1_1, "a37596ec13a0d2f9e6c0b8b96f9112823aa6d961");
	test_bits("0d", 4, LIBSHA1_1, "ba582f5967911beb91599684c2eb2baeefb78da7");
	test_bits("09", 5, LIBSHA1_1, "3320540d1c28b96ddd03eee1b186a8f2ae883fbe");
	test_bits("08", 6, LIBSHA1_1, "b372bd120957ebc3392cd060e131699d1fee6059");
	test_bits("22", 7, LIBSHA1_1, "04f31807151181ad0db278a1660526b0aeef64c2");

	test(!libsha1_hmac_init(&hs, LIBSHA1_1, "", 0));
	test(libsha1_hmac_state_output_size(&hs) == 20);
	libsha1_hmac_digest(&hs, "", 0, buf);
	libsha1_behex_lower(str, buf, libsha1_hmac_state_output_size(&hs));
	test_str(str, "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d");

	test(!libsha1_hmac_init(&hs, LIBSHA1_1, "key", 3 << 3));
	test(libsha1_hmac_state_output_size(&hs) == 20);
	libsha1_hmac_digest(&hs, "The quick brown fox jumps over the lazy dog",
	                    (sizeof("The quick brown fox jumps over the lazy dog") - 1) << 3, buf);
	libsha1_behex_lower(str, buf, libsha1_hmac_state_output_size(&hs));
	test_str(str, "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");

	n = sizeof("The quick brown fox jumps over the lazy dog") - 1;
	for (i = 1; i < n; i++) {
		test(!libsha1_hmac_init(&hs, LIBSHA1_1, "key", 3 << 3));
		test(libsha1_hmac_state_output_size(&hs) == 20);
		for (j = 0; j + i < n; j += i) {
			libsha1_hmac_update(&hs, &"The quick brown fox jumps over the lazy dog"[j], i << 3);
			test((len = libsha1_hmac_marshal(&hs, NULL)) && len <= sizeof(str));
			test(libsha1_hmac_marshal(&hs, str) == len);
			memset(&hs, 0, sizeof(hs));
			test(libsha1_hmac_unmarshal(&hs, str, sizeof(str)) == len);
		}
		libsha1_hmac_digest(&hs, &"The quick brown fox jumps over the lazy dog"[j], (n - j) << 3, buf);
		libsha1_behex_lower(str, buf, libsha1_hmac_state_output_size(&hs));
		test_str(str, "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
	}

	test(!errno);

	test_hmac(LIBSHA1_1,
	          "53616d706c65206d65737361676520666f72206b65796c656e3d626c6f636b6c656e",
	          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
	          "5fd596ee78d5553c8ff4e72d266dfd192366da29");

	test_hmac(LIBSHA1_1,
	          "53616d706c65206d65737361676520666f72206b65796c656e3c626c6f636b6c656e",
	          "000102030405060708090a0b0c0d0e0f10111213",
	          "4c99ff0cb1b31bd33f8431dbaf4d17fcd356a807");

	test_hmac(LIBSHA1_1,
	          "53616d706c65206d65737361676520666f72206b65796c656e3d626c6f636b6c656e",
	          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60616263",
	          "2d51b2f7750e410584662e38f133435f4c4fd42a");

	return 0;
}
