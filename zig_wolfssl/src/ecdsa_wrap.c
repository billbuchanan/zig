// ecdsa_wrap.c
#define WOLFSSL_USER_SETTINGS
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/ecc.h>

typedef struct EcdsaKeyHandle {
    ecc_key key;
} EcdsaKeyHandle;

EcdsaKeyHandle* ecdsa_key_new(void) {
    EcdsaKeyHandle* h = (EcdsaKeyHandle*)XMALLOC(sizeof(EcdsaKeyHandle), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (h == NULL) return NULL;

    XMEMSET(h, 0, sizeof(*h));
    if (wc_ecc_init(&h->key) != 0) {
        XFREE(h, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    return h;
}

int ecdsa_key_free(EcdsaKeyHandle* h) {
    if (h == NULL) return 0;
    wc_ecc_free(&h->key);
    XFREE(h, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return 0;
}

/* Generate an ECC keypair. For P-256, size=32 bytes. */
int ecdsa_key_make_p256(EcdsaKeyHandle* h, WC_RNG* rng) {
    if (h == NULL || rng == NULL) return BAD_FUNC_ARG;
    return wc_ecc_make_key(rng, 32, &h->key);
}

/* Export public key in X9.63 (uncompressed point) for display/debug. */
int ecdsa_export_public_x963(EcdsaKeyHandle* h, unsigned char* out, word32* outLen) {
    if (h == NULL || out == NULL || outLen == NULL) return BAD_FUNC_ARG;
    return wc_ecc_export_x963(&h->key, out, outLen);
}

/* Export private scalar (d) if available in your wolfCrypt build. */
int ecdsa_export_private_scalar(EcdsaKeyHandle* h, unsigned char* out, word32* outLen) {
    if (h == NULL || out == NULL || outLen == NULL) return BAD_FUNC_ARG;
    return wc_ecc_export_private_only(&h->key, out, outLen);
}

/* Sign a message: SHA-256(message) then ECDSA-sign-hash.
 * Output signature is DER-encoded.
 */
int ecdsa_sign_message(EcdsaKeyHandle* h, WC_RNG* rng,
                       const unsigned char* msg, word32 msgLen,
                       unsigned char* sig, word32* sigLen)
{
    int ret;
    byte digest[SHA256_DIGEST_SIZE];

    if (h == NULL || rng == NULL || msg == NULL || sig == NULL || sigLen == NULL)
        return BAD_FUNC_ARG;

    /* Hash message */
    ret = wc_Sha256Hash(msg, msgLen, digest);
    if (ret != 0) return ret;

    /* Sign hash (DER output) */
    return wc_ecc_sign_hash(digest, (word32)sizeof(digest), sig, sigLen, rng, &h->key);
}

/* Verify a message/signature: SHA-256(message) then ECDSA-verify-hash.
 * verifyRes is set to 1 on valid signature, 0 otherwise.
 */
int ecdsa_verify_message(EcdsaKeyHandle* h,
                         const unsigned char* msg, word32 msgLen,
                         const unsigned char* sig, word32 sigLen,
                         int* verifyRes)
{
    int ret;
    byte digest[SHA256_DIGEST_SIZE];

    if (h == NULL || msg == NULL || sig == NULL || verifyRes == NULL)
        return BAD_FUNC_ARG;

    ret = wc_Sha256Hash(msg, msgLen, digest);
    if (ret != 0) return ret;

    return wc_ecc_verify_hash(sig, sigLen, digest, (word32)sizeof(digest), verifyRes, &h->key);
}