// slh_dsa_wrap.c
#define WOLFSSL_USER_SETTINGS
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/sphincs.h>

#include <oqs/oqs.h> /* liboqs */

struct SlhDsaHandle {
    sphincs_key key;
    OQS_SIG* oqs;
    word32 pub_len;
    word32 prv_len;
    word32 sig_len;
};

static const char* slh_alg_name(int level, int optim) {
    /* SPHINCS+ SHAKE “simple” names used by liboqs */
    if (optim == FAST_VARIANT) {
        switch (level) {
            case 1: return "sphincs-shake-128f-simple";
            case 3: return "sphincs-shake-192f-simple";
            case 5: return "sphincs-shake-256f-simple";
            default: return NULL;
        }
    }
    else if (optim == SMALL_VARIANT) {
        switch (level) {
            case 1: return "sphincs-shake-128s-simple";
            case 3: return "sphincs-shake-192s-simple";
            case 5: return "sphincs-shake-256s-simple";
            default: return NULL;
        }
    }
    return NULL;
}

SlhDsaHandle* slh_dsa_new(int level, int optim) {
    const char* alg = slh_alg_name(level, optim);
    if (alg == NULL) return NULL;

    SlhDsaHandle* h = (SlhDsaHandle*)XMALLOC(sizeof(SlhDsaHandle), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (h == NULL) return NULL;

    XMEMSET(h, 0, sizeof(*h));

    h->oqs = OQS_SIG_new(alg);
    if (h->oqs == NULL) {
        XFREE(h, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }

    h->pub_len = (word32)h->oqs->length_public_key;
    h->prv_len = (word32)h->oqs->length_secret_key;
    h->sig_len = (word32)h->oqs->length_signature;

    if (wc_sphincs_init(&h->key) != 0) {
        OQS_SIG_free(h->oqs);
        XFREE(h, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }

    if (wc_sphincs_set_level_and_optim(&h->key, (byte)level, (byte)optim) != 0) {
        wc_sphincs_free(&h->key);
        OQS_SIG_free(h->oqs);
        XFREE(h, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }

    return h;
}

int slh_dsa_free(SlhDsaHandle* h) {
    if (h == NULL) return 0;
    wc_sphincs_free(&h->key);
    if (h->oqs) OQS_SIG_free(h->oqs);
    XFREE(h, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return 0;
}

int slh_dsa_make_key(SlhDsaHandle* h) {
    if (h == NULL || h->oqs == NULL) return BAD_FUNC_ARG;

    uint8_t* pub = (uint8_t*)XMALLOC(h->pub_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    uint8_t* prv = (uint8_t*)XMALLOC(h->prv_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pub == NULL || prv == NULL) {
        XFREE(pub, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(prv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }

    if (OQS_SIG_keypair(h->oqs, pub, prv) != OQS_SUCCESS) {
        XFREE(pub, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(prv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return RNG_FAILURE_E;
    }

    /* Import liboqs keys into wolfCrypt sphincs_key */
    int ret = wc_sphincs_import_private_key(prv, h->prv_len, pub, h->pub_len, &h->key);

    XFREE(pub, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(prv, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

/* size helpers */ 
word32 slh_dsa_pub_len(SlhDsaHandle* h) { return (h ? h->pub_len : 0); }
word32 slh_dsa_prv_len(SlhDsaHandle* h) { return (h ? h->prv_len : 0); }
word32 slh_dsa_sig_len(SlhDsaHandle* h) { return (h ? h->sig_len : 0); }

/* export */
int slh_dsa_export_public(SlhDsaHandle* h, byte* out, word32* outLen) {
    if (h == NULL || out == NULL || outLen == NULL) return BAD_FUNC_ARG;
    return wc_sphincs_export_public(&h->key, out, outLen);
}

int slh_dsa_export_private(SlhDsaHandle* h, byte* out, word32* outLen) {
    if (h == NULL || out == NULL || outLen == NULL) return BAD_FUNC_ARG;
    return wc_sphincs_export_private(&h->key, out, outLen);
}

/* sign/verify (note parameter order matches your sphincs.h) */
int slh_dsa_sign(SlhDsaHandle* h, WC_RNG* rng,
                 const byte* msg, word32 msgLen,
                 byte* sig, word32* sigLen) {
    if (h == NULL || rng == NULL || msg == NULL || sig == NULL || sigLen == NULL)
        return BAD_FUNC_ARG;
    return wc_sphincs_sign_msg(msg, msgLen, sig, sigLen, &h->key, rng);
}

int slh_dsa_verify(SlhDsaHandle* h,
                   const byte* msg, word32 msgLen,
                   const byte* sig, word32 sigLen,
                   int* verifyRes) {
    if (h == NULL || msg == NULL || sig == NULL || verifyRes == NULL)
        return BAD_FUNC_ARG;
    return wc_sphincs_verify_msg(sig, sigLen, msg, msgLen, verifyRes, &h->key);
}