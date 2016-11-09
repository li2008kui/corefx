// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Apple;
using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class AppleCrypto
    {
        private const string OidPbes2 = "1.2.840.113549.1.5.13";
        private const string OidPbkdf2 = "1.2.840.113549.1.5.12";
        private const string OidSha1 = "1.3.14.3.2.26";
        private const string OidTripleDesCbc = "1.2.840.113549.3.7";

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SecKeyExport(
            SafeSecKeyRefHandle key,
            int exportPrivate,
            SafeCreateHandle cfExportPassword,
            out SafeCFDataHandle cfDataOut,
            out int pOSStatus);

        internal static DerSequenceReader SecKeyExport(
            SafeSecKeyRefHandle key,
            bool exportPrivate)
        {
            // Apple requires all private keys to be exported encrypted, but since we're trying to export
            // as parsed structures we will need to decrypt it for the user.
            const string ExportPassword = "DotnetExportPassphrase";

            SafeCreateHandle exportPassword = exportPrivate
                ? CoreFoundation.CFStringCreateWithCString(ExportPassword)
                : new SafeCreateHandle();

            int ret;
            SafeCFDataHandle cfData;
            int osStatus;

            using (exportPassword)
            {
                ret = AppleCryptoNative_SecKeyExport(
                    key,
                    exportPrivate ? 1 : 0,
                    exportPassword,
                    out cfData,
                    out osStatus);
            }

            byte[] exportedData;

            using (cfData)
            {
                if (ret == 0)
                {
                    // TODO: Is there a better OSStatus lookup?
                    throw CreateExceptionForCCError(osStatus, "OSStatus");
                }

                if (ret != 1)
                {
                    Debug.Fail($"AppleCryptoNative_SecKeyExport returned {ret}");
                    throw new CryptographicException();
                }

                exportedData = CoreFoundation.CFGetData(cfData);
            }

            DerSequenceReader reader = new DerSequenceReader(exportedData);

            if (!exportPrivate)
            {
                return reader;
            }

            byte tag = reader.PeekTag();

            // PKCS#8 defines two structures, PrivateKeyInfo, which starts with an integer,
            // and EncryptedPrivateKey, which starts with an encryption algorithm (DER sequence).
            if (tag == (byte)DerSequenceReader.DerTag.Integer)
            {
                return reader;
            }

            const byte ConstructedSequence =
                DerSequenceReader.ConstructedFlag | (byte)DerSequenceReader.DerTag.Sequence;

            if (tag == ConstructedSequence)
            {
                return ReadEncryptedPkcs8Blob(ExportPassword, reader);
            }

            throw new CryptographicException($"Data was neither PrivateKey or EncryptedPrivateKey: {tag:X2}");
        }

        // We are using 3DES when the payload says to do so, not by choice.
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security", "CA5350")]
        private static DerSequenceReader ReadEncryptedPkcs8Blob(string passphrase, DerSequenceReader reader)
        {
            // EncryptedPrivateKeyInfo::= SEQUENCE {
            //    encryptionAlgorithm EncryptionAlgorithmIdentifier,
            //    encryptedData        EncryptedData }
            //
            // EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
            //
            // EncryptedData ::= OCTET STRING
            DerSequenceReader algorithmIdentifier = reader.ReadSequence();
            string algorithmOid = algorithmIdentifier.ReadOidAsString();

            // PBES2 (Password-Based Encryption Scheme 2)
            if (algorithmOid != OidPbes2)
            {
                throw new CryptographicException();
            }

            // PBES2-params ::= SEQUENCE {
            //    keyDerivationFunc AlgorithmIdentifier { { PBES2 - KDFs} },
            //    encryptionScheme AlgorithmIdentifier { { PBES2 - Encs} }
            // }

            DerSequenceReader pbes2Params = algorithmIdentifier.ReadSequence();
            algorithmIdentifier = pbes2Params.ReadSequence();

            string kdfOid = algorithmIdentifier.ReadOidAsString();

            // PBKDF2 (Password-Based Key Derivation Function 2)
            if (kdfOid != OidPbkdf2)
            {
                throw new CryptographicException();
            }

            // PBKDF2-params ::= SEQUENCE {
            //   salt CHOICE {
            //     specified OCTET STRING,
            //     otherSource AlgorithmIdentifier { { PBKDF2 - SaltSources} }
            //   },
            //   iterationCount INTEGER (1..MAX),
            //   keyLength INTEGER(1..MAX) OPTIONAL,
            //   prf AlgorithmIdentifier { { PBKDF2 - PRFs} }  DEFAULT algid - hmacWithSHA1
            // }
            DerSequenceReader pbkdf2Params = algorithmIdentifier.ReadSequence();

            byte[] salt = pbkdf2Params.ReadOctetString();
            int iterCount = pbkdf2Params.ReadInteger();
            int keySize = -1;

            if (pbkdf2Params.HasData && pbkdf2Params.PeekTag() == (byte)DerSequenceReader.DerTag.Integer)
            {
                keySize = pbkdf2Params.ReadInteger();
            }

            if (pbkdf2Params.HasData)
            {
                string prfOid = pbkdf2Params.ReadOidAsString();

                // SHA-1 is the only hash algorithm our PBKDF2 supports.
                if (prfOid != OidSha1)
                {
                    throw new CryptographicException(prfOid);
                }
            }

            DerSequenceReader encryptionScheme = pbes2Params.ReadSequence();
            string cipherOid = encryptionScheme.ReadOidAsString();

            // DES-EDE3-CBC (TripleDES in CBC mode)
            if (cipherOid != OidTripleDesCbc)
            {
                throw new CryptographicException();
            }

            byte[] decrypted;

            using (TripleDES des3 = TripleDES.Create())
            {
                if (keySize == -1)
                {
                    foreach (KeySizes keySizes in des3.LegalKeySizes)
                    {
                        keySize = Math.Max(keySize, keySizes.MaxSize);
                    }
                }

                byte[] iv = encryptionScheme.ReadOctetString();

                using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(passphrase, salt, iterCount))
                using (ICryptoTransform decryptor = des3.CreateDecryptor(pbkdf2.GetBytes(keySize / 8), iv))
                {
                    byte[] encrypted = reader.ReadOctetString();
                    decrypted = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
                }
            }

            DerSequenceReader pkcs8Reader = new DerSequenceReader(decrypted);
            return pkcs8Reader;
        }
    }
}