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

# X25519
Unfortunately, the WolfSSL X25519 structure is opaque, and which does not expose the size of the key. We thus have to create a wrapper for this (x25519_wrap.c):

```
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
```

We can then compile with:

```
zig build-exe zig_wolf_x25519.zig  C:\home\wolfssl-master\wolfcrypt\src\x25519_wrap.c -lc -IC:\home\wolfssl-master libwolfssl.a  -target x86_64-windows-gnu  -lws2_32
```
