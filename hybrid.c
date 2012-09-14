/*
 * hybrid.c
 * Hybrid-encryption API
 *
 * Copyright (c) 2012 William Pitcock <nenolod@dereferenced.org>.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * This software is provided 'as is' and without any warranty, express or
 * implied.  In no event shall the authors be liable for any damages arising
 * from the use of this software.
 */

#include "stdinc.h"
#include "hybrid.h"

#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>

/* from https://gitweb.torproject.org/torspec.git/blob/HEAD:/tor-spec.txt, PK_PAD_LEN = 42 */
#define PADDING_OVERHEAD 42
#define AES_KEY_SIZE     128/8

void torbounce_aes_encrypt(unsigned char *key, size_t key_len, unsigned char *out, unsigned char *in, size_t in_len)
{
	AES_KEY keystore;
	unsigned char iv[AES_BLOCK_SIZE];
	unsigned char scratch[AES_BLOCK_SIZE];
	unsigned int ctr = 0;

	memset(iv, '\0', sizeof iv);
	memset(scratch, '\0', sizeof scratch);

	AES_set_encrypt_key(key, key_len, &keystore);
	AES_ctr128_encrypt(in, out, in_len, &keystore, iv, scratch, &ctr);
}

/*
 * 0.3. Ciphers.
 *
 * [...]
 *
 * The "hybrid encryption" of a byte sequence M with a public key PK is
 * computed as follows:
 *
 * 1. If M is less than PADDING_OVERHEAD, pad and encrypt M with PK.
 * 2. Otherwise, generate a KEY_LEN byte random K.  Let M1 = the first 186 bytes
 *    of M, and let M2 = the rest of M.
 *    Pad and encrypt K|M1 with PK.  Encrypt M2 with our stream cipher, using the
 *    key K.  Concatenate these encrypted values.
 */
static void torbounce_aes_encrypt_hybrid_chunk(RSA *rsa, unsigned char *in, size_t in_len, unsigned char **out, size_t *out_len)
{
	size_t pk_len = RSA_size(rsa);
	size_t m1_len = pk_len - PADDING_OVERHEAD - AES_KEY_SIZE;
	size_t m2_len = in_len - m1_len;
	unsigned char symkey[AES_KEY_SIZE];
	unsigned char *envelope;

	*out_len = pk_len + m2_len;
	*out = malloc(*out_len);

	RAND_bytes(symkey, sizeof symkey);

	envelope = malloc(pk_len - PADDING_OVERHEAD);
	memcpy(envelope, symkey, sizeof symkey);
	memcpy(envelope + sizeof symkey, in, m1_len);

	RSA_public_encrypt(pk_len - PADDING_OVERHEAD, envelope, *out, rsa, RSA_PKCS1_OAEP_PADDING);
	torbounce_aes_encrypt(symkey, sizeof symkey, (*out) + pk_len, in + m1_len, m2_len);

	free(envelope);
}

static void torbounce_aes_encrypt_single_chunk(RSA *rsa, unsigned char *in, size_t in_len, unsigned char **out, size_t *out_len)
{
	*out_len = RSA_size(rsa);
	*out = malloc(*out_len);

	RSA_public_encrypt(in_len, in, *out, rsa, RSA_PKCS1_OAEP_PADDING);
}

void torbounce_encrypt_chunk(RSA *rsa, unsigned char *in, size_t in_len, unsigned char **out, size_t *out_len)
{
	if (in_len < (RSA_size(rsa) - PADDING_OVERHEAD))
	{
		torbounce_aes_encrypt_single_chunk(rsa, in, in_len, out, out_len);
		return;
	}

	torbounce_aes_encrypt_hybrid_chunk(rsa, in, in_len, out, out_len);
}
