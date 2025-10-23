/*
 * This library implements the stream cipher Sosemanuk
 * Author - C. Berbain, O. Billet, A. Canteaut, N. Courtois, H. Gilbert, L. Goubin,
 * A. Gouget, L. Granboulan, C. Lauradoux, M. Minier, T. Pornin and H. Sibert
 * Sosemanuk - the winner eSTREAM Project. Home page - http://www.ecrypt.eu.org/stream/
*/

#ifndef SOSEMANUK_H
#define SOSEMANUK_H

/*
 * Sosemanuk context
 * keylen - chipher key length in bytes
 * ivlen - vector initialization length in bytes
 * key - chiper key
 * iv - initialization vector
 * sk - array subkey for Serpent24
 * s - array internal cipher state
 * r1 - internal cipher state
 * r2 - internal cipher state
*/
struct sosemanuk_context {
	int keylen;
	int ivlen;
	uint8_t key[32];
	uint8_t iv[16];
	uint32_t sk[100];
	uint32_t s[10];
	uint32_t r1;
	uint32_t r2;
};

int sosemanuk_set_key_and_iv(struct sosemanuk_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[16], const int ivlen);

void sosemanuk_crypt(struct sosemanuk_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);

void sosemanuk_test_vectors(struct sosemanuk_context *ctx);

void sosemanuk_generate_keystream(struct sosemanuk_context *ctx, uint32_t *keystream);

#endif
