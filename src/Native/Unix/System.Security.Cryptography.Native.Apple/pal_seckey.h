// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma once

#include "pal_types.h"

#include <Security/Security.h>

// Unless another interpretation is "obvious", pal_seckey functions return 1 on success.
// functions which represent a boolean return 0 on "successful false"
// otherwise functions will return one of the following return values:
static const int kErrorBadInput = -1;
static const int kErrorSeeError = -2;
static const int kErrorUnknownAlgorithm = -3;
static const int kErrorUnknownState = -4;

/*
Export a key object.

Public keys are exported using the "OpenSSL" format option, which means, essentially,
"whatever format the openssl CLI would use for this algorithm by default".

Private keys are exported using the "Wrapped PKCS#8" format. These formats are available via
`openssl pkcs8 -topk8 ...`. While the PKCS#8 container is the same for all key types, the
payload is algorithm-dependent (though identified by the PKCS#8 wrapper).

An export passphrase is required for private keys, and ignored for public keys.

Follows pal_seckey return conventions.
*/
extern "C" int32_t AppleCryptoNative_SecKeyExport(
    SecKeyRef pKey, int32_t exportPrivate, CFStringRef cfExportPassphrase, CFDataRef* ppDataOut, int32_t* pOSStatus);

/*
Import a key from a key blob.

Imports are always done using the "OpenSSL" format option, which means the format used for an
unencrypted private key via the openssl CLI verb of the algorithm being imported.

For public keys the "OpenSSL" format is NOT the format used by the openssl CLI for that algorithm,
but is in fact the X.509 SubjectPublicKeyInfo structure.

Returns 1 on success, 0 on failure (*pOSStatus should be set) and negative numbers for various
state machine errors.
*/
extern "C" int32_t AppleCryptoNative_SecKeyImportEphemeral(
    uint8_t* pbKeyBlob, int32_t cbKeyBlob, int32_t isPrivateKey, SecKeyRef* ppKeyOut, int32_t* pOSStatus);

/*
For RSA and DSA this function returns the number of bytes in "the key", which corresponds to
the length of n/Modulus for RSA and for P in DSA.

For ECC the value should not be used.

0 is returned for invalid inputs.
*/
extern "C" uint64_t AppleCryptoNative_SecKeyGetSimpleKeySizeInBytes(SecKeyRef publicKey);

/*
Get a CFRetain()ed SecKeychainRef value for the keychain to which the keychain item belongs.

The behavior of this function is undefined if `item` is not a CFTypeRef.
For types that are not understood by this function to be keychain items an invalid parameter error is returned.
Errors of the item having no keychain are suppressed, returning success (0) with *pKeychainOut set to NULL.

For all other situations, see SecKeychainItemCopyKeychain documentation.
*/
extern "C" int32_t AppleCryptoNative_SecKeychainItemCopyKeychain(SecKeychainItemRef item, SecKeychainRef* pKeychainOut);

/*
Create a keychain at the specified location with a given (UTF-8 encoded) lock passphrase.

Returns the result of SecKeychainCreate.

Output:
pKeychainOut: The SecKeychainRef created by this function
*/
extern "C" int32_t AppleCryptoNative_SecKeychainCreate(const char* pathName,
                                                       uint32_t passphraseLength,
                                                       const uint8_t* passphraseUtf8,
                                                       SecKeychainRef* pKeychainOut);

/*
Delete a keychain, including the file on disk.

Returns the result of SecKeychainDelete
*/
extern "C" int32_t AppleCryptoNative_SecKeychainDelete(SecKeychainRef keychain);

/*
Open the default keychain.
This is usually login.keychain, but can be adjusted by the user.

Returns the result of SecKeychainCopyDefault.

Output:
pKeyChainOut: Receives the SecKeychainRef for the default keychain.
*/
extern "C" int32_t AppleCryptoNative_SecKeychainCopyDefault(SecKeychainRef* pKeychainOut);

    /*
    Open the named keychain (full path to the file).

    Returns the result of SecKeychainOpen.

    Output:
    pKeychainOut: Receives the SecKeychainRef for the named keychain.
    */
    extern "C" int32_t AppleCryptoNative_SecKeychainOpen(const char* pszKeychainPath, SecKeychainRef* pKeychainOut);

/*
Enumerate the certificate objects within the given keychain.

Returns 1 on success (including "no certs found"), 0 on failure, any other value for invalid state.

Output:
pCertsOut: When the return value is not 1, NULL. Otherwise NULL on "no certs found", or a CFArrayRef for the matches
(including a single match).
pOSStatus: Receives the last OSStatus value.
*/
extern "C" int32_t
AppleCryptoNative_SecKeychainEnumerateCerts(SecKeychainRef keychain, CFArrayRef* pCertsOut, int32_t* pOSStatus);

/*
Enumerate the certificate objects within the given keychain.

Returns 1 on success (including "no certs found"), 0 on failure, any other value for invalid state.

Note that any identity will also necessarily be returned as a certificate with no private key by
SecKeychainEnumerateCerts.  De-duplication of values is the responsibility of the caller.

Output:
pCertsOut: When the return value is not 1, NULL. Otherwise NULL on "no certs found", or a CFArrayRef for the matches
(including a single match).
pOSStatus: Receives the last OSStatus value.
*/
extern "C" int32_t AppleCryptoNative_SecKeychainEnumerateIdentities(SecKeychainRef keychain,
                                                                    CFArrayRef* pIdentitiesOut,
                                                                    int32_t* pOSStatus);
