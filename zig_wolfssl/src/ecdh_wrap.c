// ecc_wrap.c
#define WOLFSSL_USER_SETTINGS
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>


ecc_key* ecc_new(void) {
    ecc_key* k = (ecc_key*)XMALLOC(sizeof(ecc_key), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!k) return NULL;

    if (wc_ecc_init(k) != 0) {
        XFREE(k, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    return k;
}

int ecc_delete(ecc_key* k) {
    if (!k) return 0;
    wc_ecc_free(k);
    XFREE(k, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return 0;
}

int ecc_make_key(ecc_key* k, WC_RNG* rng) {
    return wc_ecc_make_key(rng, 32, k);   // 32 bytes → P-256
}

int ecc_export_public(ecc_key* k, unsigned char* out, word32* outLen) {
    return wc_ecc_export_x963(k, out, outLen);
}

int ecc_import_public(ecc_key* k, const unsigned char* in, word32 len) {
    return wc_ecc_import_x963(in, len, k);
}

int ecc_shared_secret(ecc_key* priv, ecc_key* pub, unsigned char* out, word32* outLen) {
    return wc_ecc_shared_secret(priv, pub, out, outLen);
}


int ecc_export_private_scalar(ecc_key* k, unsigned char* out, word32* outLen)
{
    if (k == NULL || out == NULL || outLen == NULL)
        return BAD_FUNC_ARG;

    /* Exports the private scalar 'd' only */
    return wc_ecc_export_private_only(k, out, outLen);
}