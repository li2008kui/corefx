Cross-Platform Cryptography
===========================

Cryptographic operations in .NET are performed by existing system libraries.
As with most technological decisions, there are various pros and cons.
Since the system already has a vested interested in making the cryptography libraries safe from security vulnerabilities,
and already has an update mechanism that system administrators should be using, .NET gets to benefit from this reliability.
Users who have requirements to use FIPS-validated algorithm implementations also get that benefit for free (when the system
libraries are FIPS-validated, of course).The biggest con is that not all system libraries offer the same capabilities.
While the core capabilities are present across the various platforms, there are some rough edges.

## Hash Algorithms

Hash algorithms, and HMAC algorithms, are very standard bytes-in-bytes-out operations.
All hash algorithm (and HMAC) classes in .NET Core are deferred to the system libraries (including the \*Managed classes).

While the various system libraries may have different performance, there should not be concerns of compatibility.

In the future there is a possibility that new hash algorithms may be added to .NET Core before one (or more) supported platforms have system support for the algorithm.This would result in a `PlatformNotSupportedException` when invoking the `.Create()` method for the algorithm.

## Symmetric Encryption

The underlying ciphers and chaining are performed by the system libraries.

AES, TripleDES, and DES are supported on all platforms.
CBC and ECB are supported on all platforms.

In the future there is a possibility that new ciphers may be added to .NET Core before one (or more) supported platforms have system support for it.
This would result in a `PlatformNotSupportedException` when invoking the `.Create()` method for the algorithm.

In the future there is a possibility that new cipher/chaining modes may be added to .NET Core before one (or more) supported platforms have system support for it.
This would result in a `PlatformNotSupportedException` when invoking the `.CreateEncryptor()` or `.CreateDecryptor()` methods for the algorithm (or overloads to those methods).

In the future there is a possiblity that new cipher/chaining modes may be added to .NET Core which do not apply to all symmetric algorithms.
This would likely result in a `NotSupportedException` when using the set-accessor of the `.Mode` property on the `SymmetricAlgorithm` object, but this prediction is subject to change.

## RSA

RSA key generation is performed by the system libraries, and is subject to size limitations and performance characteristics thereof.
RSA key operations are performed by the system libraries, and the types of key that may be loaded are subject to system requirements.

.NET Core does not expose "raw" (unpadded) RSA operations, and .NET Core relies on the system libraries for encryption (and decryption) padding.
Not all platforms support the same padding options.

| Padding Mode | Windows (CNG) | Linux (OpenSSL) | macOS | Windows (CAPI) |
|--------------|---------------|-----------------|-------|----------------|
| PKCS1 Encryption | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| OAEP - SHA-1 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| OAEP - SHA-2 (SHA256, SHA384, SHA512) | :white_check_mark: | :x: | :x: | :x: |
| PKCS1 Signature (MD5, SHA-1) |  :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| PKCS1 Signature (SHA-2) |  :white_check_mark: | :white_check_mark: | :white_check_mark: | :question: |
| PSS |  :white_check_mark: | :x: | :x: | :x: |

Windows CNG is used on Windows whenever `RSA.Create()` or `new RSACng()` is used, as well as the `.GetRSAPublicKey()` extension method for `X509Certificate2` and when possible for the `.GetRSAPrivateKey()` extension method for `X509Certificate2`.
Windows CAPI is used on Windows whenever `new RSACryptoServiceProvider()` is used, as well as the `GetRSAPrivateKey()` extension method when the private key is not able to be opened with CNG (which requires a hardware-backed key with no CNG-capable driver).

macOS should refer to the Linux (OpenSSL) column for .NET Core versions 1.0 and 1.1.

Windows CAPI is capable of PKCS1 signature with a SHA-2 algorithm, but the individual RSA object may be loaded in a CSP which does not support it.

## ECDSA

ECDSA key generation is performed by the system libraries, and is subject to size limitations and performance characteristics thereof.
ECDSA key curves are defined by the system libraries, and are subject to the limitations thereof.

| EC Curve | Windows 10 | Linux | macOS | Windows 7 - 8.1 |
|----------|------------|-------|-------|-----------------|
| NIST P-256 (secp256r1) | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| NIST P-384 (secp384r1) | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| NIST P-521 (secp521r1) | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| brainpool curves (as named curves) | :white_check_mark: | :question: | :x: | :x: |
