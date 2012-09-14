/*
 * hybrid.h
 * Hybrid-encryption API headers.
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

#include <openssl/rsa.h>
#include <openssl/aes.h>

#ifndef __HYBRID_H__
#define __HYBRID_H__

extern void torbounce_aes_encrypt(unsigned char *key, size_t key_len, unsigned char *out, unsigned char *in, size_t in_len);
extern void torbounce_encrypt_chunk(RSA *rsa, unsigned char *in, size_t in_len, unsigned char **out, size_t *out_len);

#endif
