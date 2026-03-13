#include "slh_dsa_oqs_wrap.h"

#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

struct SlhDsaHandle {
    OQS_SIG* oqs;
    uint8_t* pub;
    uint8_t* prv;
    size_t pub_len;
    size_t prv_len;
    size_t sig_len;
};

static const char* slh_alg_name(int level, int optim) {
    if (optim == 1) {
        switch (level) {
            case 1: return OQS_SIG_alg_sphincs_shake_128f_simple;
            case 3: return OQS_SIG_alg_sphincs_shake_192f_simple;
            case 5: return OQS_SIG_alg_sphincs_shake_256f_simple;
            default: return NULL;
        }
    }
    if (optim == 2) {
        switch (level) {
            case 1: return OQS_SIG_alg_sphincs_shake_128s_simple;
            case 3: return OQS_SIG_alg_sphincs_shake_192s_simple;
            case 5: return OQS_SIG_alg_sphincs_shake_256s_simple;
            default: return NULL;
        }
    }
    return NULL;
}

int slh_dsa_new(int level, int optim, SlhDsaHandle** out) {
    const char* alg;
    SlhDsaHandle* h;

    if (out == NULL) return -1;
    *out = NULL;

    alg = slh_alg_name(level, optim);
    if (alg == NULL) return -2;

    if (!OQS_SIG_alg_is_enabled(alg)) return -3;

    h = (SlhDsaHandle*)calloc(1, sizeof(*h));
    if (h == NULL) return -4;

    h->oqs = OQS_SIG_new(alg);
    if (h->oqs == NULL) {
        free(h);
        return -5;
    }

    h->pub_len = h->oqs->length_public_key;
    h->prv_len = h->oqs->length_secret_key;
    h->sig_len = h->oqs->length_signature;

    h->pub = (uint8_t*)malloc(h->pub_len);
    h->prv = (uint8_t*)malloc(h->prv_len);
    if (h->pub == NULL || h->prv == NULL) {
        free(h->pub);
        free(h->prv);
        OQS_SIG_free(h->oqs);
        free(h);
        return -6;
    }

    *out = h;
    return 0;
}

int slh_dsa_free(SlhDsaHandle* h) {
    if (h == NULL) return 0;

    if (h->pub != NULL) {
        memset(h->pub, 0, h->pub_len);
        free(h->pub);
    }
    if (h->prv != NULL) {
        memset(h->prv, 0, h->prv_len);
        free(h->prv);
    }
    if (h->oqs != NULL) {
        OQS_SIG_free(h->oqs);
    }
    free(h);
    return 0;
}

int slh_dsa_make_key(SlhDsaHandle* h) {
    if (h == NULL || h->oqs == NULL || h->pub == NULL || h->prv == NULL) return -1;
    return (OQS_SIG_keypair(h->oqs, h->pub, h->prv) == OQS_SUCCESS) ? 0 : -2;
}

size_t slh_dsa_pub_len(const SlhDsaHandle* h) {
    return h ? h->pub_len : 0;
}

size_t slh_dsa_prv_len(const SlhDsaHandle* h) {
    return h ? h->prv_len : 0;
}

size_t slh_dsa_sig_len(const SlhDsaHandle* h) {
    return h ? h->sig_len : 0;
}

int slh_dsa_export_public(const SlhDsaHandle* h, uint8_t* out, size_t* out_len) {
    if (h == NULL || out_len == NULL) return -1;
    if (*out_len < h->pub_len) {
        *out_len = h->pub_len;
        return -2;
    }
    if (out == NULL) return -3;

    memcpy(out, h->pub, h->pub_len);
    *out_len = h->pub_len;
    return 0;
}

int slh_dsa_export_private(const SlhDsaHandle* h, uint8_t* out, size_t* out_len) {
    if (h == NULL || out_len == NULL) return -1;
    if (*out_len < h->prv_len) {
        *out_len = h->prv_len;
        return -2;
    }
    if (out == NULL) return -3;

    memcpy(out, h->prv, h->prv_len);
    *out_len = h->prv_len;
    return 0;
}

int slh_dsa_sign(
    const SlhDsaHandle* h,
    const uint8_t* msg,
    size_t msg_len,
    uint8_t* sig,
    size_t* sig_len
) {
    OQS_STATUS rc;

    if (h == NULL || h->oqs == NULL || msg == NULL || sig == NULL || sig_len == NULL) return -1;

    rc = OQS_SIG_sign(h->oqs, sig, sig_len, msg, msg_len, h->prv);
    return (rc == OQS_SUCCESS) ? 0 : -2;
}

int slh_dsa_verify(
    const SlhDsaHandle* h,
    const uint8_t* msg,
    size_t msg_len,
    const uint8_t* sig,
    size_t sig_len,
    int* verify_res
) {
    OQS_STATUS rc;

    if (h == NULL || h->oqs == NULL || msg == NULL || sig == NULL || verify_res == NULL) return -1;

    rc = OQS_SIG_verify(h->oqs, msg, msg_len, sig, sig_len, h->pub);
    *verify_res = (rc == OQS_SUCCESS) ? 1 : 0;
    return 0;
}