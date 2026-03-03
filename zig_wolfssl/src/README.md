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
