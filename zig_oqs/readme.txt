# Zig and Liboqs
Compilation:

```
zig build-exe zig_liboqs_mldsa.zig -I C:\home\liboqs\build\include  -lc liboqs.lib -target x86_64-windows
```

## Liboqs

* ML-DSA, SLH-DSA, Falcon and other PQC Signatures with Liboqs and Zig [ here] ML-DSA, SLH-DSA, Falcon and other PQC Signatures with Liboqs and Zig.
* ML-KEM, Kyber, McEliece, NTRU, FrodoHEM and sntrup761 using liboqs and Zig [ here]. NIST has standardised ML-KEM (aka Kyber) within FIPS 203, and has also defined that HQC will become a KEM (Key Encapsulation Method) standard. There are other alternatives to ML-KEM, including sntrup761, McEliece and FrodoKEM. In this case, we will generate a key pair for each of the main types, and then encapsulate a secret with a public key which can be decapsulated with the associated private key.
