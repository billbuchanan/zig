# ML-DSA
To build:

```
zig build-exe zig_wolf_mldsa.zig -lc -IC:\home\wolfssl-master libwolfssl.a  -target x86_64-windows-gnu -lws2_32
```
and the user_settings.h file is:
```
#define HAVE_ECC 
#define HAVE_WOLFSSL_CURVE25519 
#define HAVE_DILITHIUM 
#define WOLFSSL_WC_DILITHIUM 

#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256

#define HAVE_WOLFSSL_MD5 
#define HAVE_WOLFSSL_RIPEMD 
#define HAVE_WOLFSSL_SHA384 
#define HAVE_WOLFSSL_SHA512 
#define HAVE_WOLFSSL_AESGCM 
#define HAVE_WOLFSSL_CHACHA 
#define HAVE_WOLFSSL_POLY1305 
#define HAVE_WOLFSSL_CMAC 
#define HAVE_WOLFSSL_SM3 
#define HAVE_WOLFSSL_CAMELLIA 

#define HAVE_BLAKE2B 
#define HAVE_BLAKE2S 
#define HAVE_BLAKE2

#define WOLFSSL_MD2
#define WOLFSSL_MD5 
#define WOLFSSL_SHA3 
#define WOLFSSL_SHA224 
#define WOLFSSL_SHA384 
#define WOLFSSL_SHA512 

#define WOLFSSL_RIPEMD 

#define WOLFSSL_BLAKE2 
#define WOLFSSL_BLAKE2B
#define WOLFSSL_BLAKE2S


/* Make sure these are NOT enabled */ 
#undef WOLFSSL_SMALL_STACK 
#undef WOLFSSL_ECC_POINT_IS_OPAQUE
```

# ML-KEM
Unfortunately, the WolfSSL ML-KEM structure is opaque, and which does not expose the size of the key. We thus have to create a wrapper for this (mlkem_wrap.c):

```
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
    if (k == NULL) return 0;
    (void)wc_MlKemKey_Free(k);
    XFREE(k, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return 0;
}
```

We also need to integrate liboqs.a, and can then compile with:

```
zig build-exe zig_wolf_mlkem.zig  C:\home\wolfssl-master\wolfcrypt\src\mlkem_wrap.c -lc -IC:\home\wolfssl-master libwolfssl.a  -target x86_64-windows-gnu liboqs.a -lws2_32
```
