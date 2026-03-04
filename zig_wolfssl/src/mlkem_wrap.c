#include <wolfssl/wolfcrypt/mlkem.h>


MlKemKey* mlkem_new(int type) {
    MlKemKey* k = (MlKemKey*)XMALLOC(sizeof(MlKemKey), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (k == NULL) return NULL;
    if (wc_MlKemKey_Init(k, type, NULL, INVALID_DEVID) != 0) {
        XFREE(k, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    return k;
}

int mlkem_delete(MlKemKey* k) {
    if (k == NULL) return BAD_FUNC_ARG;
    (void)wc_MlKemKey_Free(k);
    XFREE(k, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return 0;
}