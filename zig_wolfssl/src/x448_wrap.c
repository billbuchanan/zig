// curve448_wrap.c

#define WOLFSSL_USER_SETTINGS
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/curve448.h>

#define ECC_448_BIT_FIELD 56 // 448-bit curve field

/* Allocate + init a CurveX448 (X25519) key */
curve448_key* curve448_new(void) {
    curve448_key* k = (curve448_key*)XMALLOC(sizeof(curve448_key),
        NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (k == NULL) return NULL;

    if (wc_curve448_init(k) != 0) {
        XFREE(k, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    return k;
}

/* Free + deallocate */
int curve448_delete(curve448_key* k) {
    if (k == NULL) return 0;
    wc_curve448_free(k);
    XFREE(k, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return 0;
}

/* Generate a keypair (private+public) */
int curve448_make_key(curve448_key* k, WC_RNG* rng) {
    if (k == NULL || rng == NULL) return BAD_FUNC_ARG;
    return wc_curve448_make_key(rng, ECC_448_BIT_FIELD, k); 
}

/* Export raw 32-byte public key */
int curve448_export_public(curve448_key* k, unsigned char* out32, word32* outLen) {
    if (k == NULL || out32 == NULL || outLen == NULL) return BAD_FUNC_ARG;
    return wc_curve448_export_public(k, out32, outLen);
}

/* Import a raw 32-byte public key into a key object (public-only) */
int curve448_import_public(curve448_key* k, const unsigned char* in32, word32 inLen) {
    if (k == NULL || in32 == NULL) return BAD_FUNC_ARG;
    return wc_curve448_import_public(in32, inLen, k);
}

/* Compute shared secret. outLen must be set to capacity (usually 32). */
int curve448_shared_secret(curve448_key* myPriv,
                         curve448_key* theirPub,
                         unsigned char* out,
                         word32* outLen) {
    if (myPriv == NULL || theirPub == NULL || out == NULL || outLen == NULL)
        return BAD_FUNC_ARG;
    return wc_curve448_shared_secret(myPriv, theirPub, out, outLen);
}

int curve448_export_private(curve448_key* k, unsigned char* out32, word32* outLen) {
    if (k == NULL || out32 == NULL || outLen == NULL)
        return BAD_FUNC_ARG;

    return wc_curve448_export_private_raw(k, out32, outLen);
}