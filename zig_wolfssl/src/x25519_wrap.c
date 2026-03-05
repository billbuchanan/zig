// x25519_wrap.c
#define WOLFSSL_USER_SETTINGS
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/curve25519.h>

/* Allocate + init a Curve25519 (X25519) key */
curve25519_key* x25519_new(void) {
    curve25519_key* k = (curve25519_key*)XMALLOC(sizeof(curve25519_key),
        NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (k == NULL) return NULL;

    if (wc_curve25519_init(k) != 0) {
        XFREE(k, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    return k;
}

/* Free + deallocate */
int x25519_delete(curve25519_key* k) {
    if (k == NULL) return 0;
    wc_curve25519_free(k);
    XFREE(k, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return 0;
}

/* Generate a keypair (private+public) */
int x25519_make_key(curve25519_key* k, WC_RNG* rng) {
    if (k == NULL || rng == NULL) return BAD_FUNC_ARG;
    return wc_curve25519_make_key(rng, 32, k); /* 32 bytes for X25519 */
}

/* Export raw 32-byte public key */
int x25519_export_public(curve25519_key* k, unsigned char* out32, word32* outLen) {
    if (k == NULL || out32 == NULL || outLen == NULL) return BAD_FUNC_ARG;
    return wc_curve25519_export_public(k, out32, outLen);
}

/* Import a raw 32-byte public key into a key object (public-only) */
int x25519_import_public(curve25519_key* k, const unsigned char* in32, word32 inLen) {
    if (k == NULL || in32 == NULL) return BAD_FUNC_ARG;
    return wc_curve25519_import_public(in32, inLen, k);
}

/* Compute shared secret. outLen must be set to capacity (usually 32). */
int x25519_shared_secret(curve25519_key* myPriv,
                         curve25519_key* theirPub,
                         unsigned char* out,
                         word32* outLen) {
    if (myPriv == NULL || theirPub == NULL || out == NULL || outLen == NULL)
        return BAD_FUNC_ARG;
    return wc_curve25519_shared_secret(myPriv, theirPub, out, outLen);
}

int x25519_export_private(curve25519_key* k, unsigned char* out32, word32* outLen) {
    if (k == NULL || out32 == NULL || outLen == NULL)
        return BAD_FUNC_ARG;

    return wc_curve25519_export_private_raw(k, out32, outLen);
}