# Integration with liboqs

Here are two examples:

* ML-DSA, SLH-DSA, Falcon and other PQC Signatures with Liboqs and Zig [here](https://asecuritysite.com/zig/zig_oqs_mldsa). ML-DSA, SLH-DSA, Falcon and other PQC Signatures with Liboqs and Zig.
* ML-KEM, Kyber, McEliece, NTRU, FrodoHEM and sntrup761 using liboqs and Zig [here](https://asecuritysite.com/zig/zig_liboqs_kem). NIST has standardised ML-KEM (aka Kyber) within FIPS 203, and has also defined that HQC will become a KEM (Key Encapsulation Method) standard. There are other alternatives to ML-KEM, including sntrup761, McEliece and FrodoKEM. In this case, we will generate a key pair for each of the main types, and then encapsulate a secret with a public key and then which can be decapsulated with the associated private key. 
