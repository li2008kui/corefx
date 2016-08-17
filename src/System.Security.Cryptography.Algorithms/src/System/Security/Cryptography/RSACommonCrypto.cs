// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.Apple;
using Internal.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography
{
    public partial class RSA : AsymmetricAlgorithm
    {
        public static RSA Create()
        {
            return new RSAImplementation.RSASecurityTransforms();
        }
    }

    internal static partial class RSAImplementation
    {
        // TODO: Name this for real.
        public sealed partial class RSASecurityTransforms : RSA
        {
            private SafeSecKeyRefHandle _privateKey;
            private SafeSecKeyRefHandle _publicKey;

            public override RSAParameters ExportParameters(bool includePrivateParameters)
            {
                SafeCFDataHandle cfData;
                int osStatus;

                SafeSecKeyRefHandle keyHandle = includePrivateParameters ? _privateKey : _publicKey;

                if (keyHandle == null)
                {
                    throw new CryptographicException("No key handle allocated");
                }

                int ret = Interop.AppleCrypto.RsaExportKey(
                    keyHandle,
                    out cfData,
                    out osStatus);

                if (ret == 0)
                {
                    // TODO: Is there a better OSStatus lookup?
                    throw Interop.AppleCrypto.CreateExceptionForCCError(osStatus, "OSStatus");
                }

                if (ret != 1)
                {
                    Debug.Assert(ret == 0, $"RsaExportKey returned {ret}");
                    throw new CryptographicException();
                }

                byte[] encryptedPrivateKey = Interop.CoreFoundation.CFGetData(cfData);
                RSAParameters parameters = new RSAParameters();
                encryptedPrivateKey.ConvertPkcs8Blob(ref parameters);
                return parameters;
            }

            public override void ImportParameters(RSAParameters parameters)
            {
                byte[] pkcs1Blob = parameters.ToPkcs1Blob();
                SafeSecKeyRefHandle keyHandle;
                int osStatus;
                bool isPrivateKey = parameters.D != null;

                int ret = Interop.AppleCrypto.RsaImportEphemeralKey(
                    pkcs1Blob,
                    pkcs1Blob.Length,
                    isPrivateKey,
                    out keyHandle,
                    out osStatus);

                if (ret == 1 && !keyHandle.IsInvalid)
                {
                    if (isPrivateKey)
                    {
                        _privateKey = keyHandle;
                        _publicKey = keyHandle;
                    }
                    else
                    {
                        _publicKey = keyHandle;
                        _privateKey = keyHandle;
                    }

                    return;
                }

                keyHandle.Dispose();

                if (ret == 0)
                {
                    // TODO: Is there a better OSStatus lookup?
                    throw Interop.AppleCrypto.CreateExceptionForCCError(osStatus, "OSStatus");
                }

                if (ret != 1)
                {
                    Debug.Assert(ret != -1, "Shim indicates invalid inputs");
#if DEBUG
                    throw new CryptographicException($"RsaImportEphemeralKey returned {ret}");
#endif
                }

                throw new CryptographicException();
            }

            public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding)
            {
                throw new NotImplementedException();
            }

            public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding)
            {
                throw new NotImplementedException();
            }

            public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
            {
                throw new NotImplementedException();
            }

            public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
            {
                if (padding != RSASignaturePadding.Pkcs1)
                    throw new CryptographicException(SR.Cryptography_InvalidPaddingMode);

                return Interop.AppleCrypto.RsaVerify(
                    _publicKey,
                    hash,
                    signature,
                    PalAlgorithmFromAlgorithmName(hashAlgorithm));
            }

            protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
            {
                return OpenSslAsymmetricAlgorithmCore.HashData(data, offset, count, hashAlgorithm);
            }

            protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm)
            {
                return OpenSslAsymmetricAlgorithmCore.HashData(data, hashAlgorithm);
            }

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    _privateKey?.Dispose();
                    _publicKey?.Dispose();
                    _privateKey = null;
                    _publicKey = null;
                }

                base.Dispose(disposing);
            }

            private static Interop.AppleCrypto.PAL_HashAlgorithm PalAlgorithmFromAlgorithmName(
                HashAlgorithmName hashAlgorithmName)
            {
                if (hashAlgorithmName == HashAlgorithmName.MD5)
                {
                    return Interop.AppleCrypto.PAL_HashAlgorithm.Md5;
                }
                else if (hashAlgorithmName == HashAlgorithmName.SHA1)
                {
                    return Interop.AppleCrypto.PAL_HashAlgorithm.Sha1;
                }
                else if (hashAlgorithmName == HashAlgorithmName.SHA256)
                {
                    return Interop.AppleCrypto.PAL_HashAlgorithm.Sha256;
                }
                else if (hashAlgorithmName == HashAlgorithmName.SHA384)
                {
                    return Interop.AppleCrypto.PAL_HashAlgorithm.Sha384;
                }
                else if (hashAlgorithmName == HashAlgorithmName.SHA512)
                {
                    return Interop.AppleCrypto.PAL_HashAlgorithm.Sha512;
                }

                throw new CryptographicException(SR.Cryptography_UnknownHashAlgorithm, hashAlgorithmName.Name);
            }
        }
    }

    internal static class Pkcs1BlobHelpers
    {
        // The PKCS#1 version blob for an RSA key based on 2 primes.
        private static readonly byte[] s_versionNumberBytes = { 0 };

        internal static byte[] ToPkcs1Blob(this RSAParameters parameters)
        {
            if (parameters.Exponent == null || parameters.Modulus == null)
                throw new CryptographicException(SR.Cryptography_InvalidRsaParameters);

            if (parameters.D == null)
            {
                if (parameters.P != null ||
                    parameters.DP != null ||
                    parameters.Q != null ||
                    parameters.DQ != null ||
                    parameters.InverseQ != null)
                {
                    throw new CryptographicException(SR.Cryptography_InvalidRsaParameters);
                }

                return DerEncoder.ConstructSequence(
                    DerEncoder.SegmentedEncodeUnsignedInteger(parameters.Modulus),
                    DerEncoder.SegmentedEncodeUnsignedInteger(parameters.Exponent));
            }

            if (parameters.P == null ||
                parameters.DP == null ||
                parameters.Q == null ||
                parameters.DQ == null ||
                parameters.InverseQ == null)
            {
                throw new CryptographicException(SR.Cryptography_InvalidRsaParameters);
            }

            return DerEncoder.ConstructSequence(
                DerEncoder.SegmentedEncodeUnsignedInteger(s_versionNumberBytes),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.Modulus),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.Exponent),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.D),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.P),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.Q),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.DP),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.DQ),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.InverseQ));
        }

        internal static void ConvertPkcs8Blob(this byte[] blob, ref RSAParameters parameters)
        {
            Debug.Assert(blob != null);

            DerSequenceReader reader = new DerSequenceReader(blob);
            byte tag = reader.PeekTag();

            // PKCS#8 defines two structures, PrivateKeyInfo, which starts with an integer,
            // and EncryptedPrivateKey, which starts with an encryption algorithm (DER sequence).

            if (tag == (byte)DerSequenceReader.DerTag.Integer)
            {
                ReadPkcs8Blob(reader, ref parameters);
                return;
            }

            if (tag == 0x30)
            {
                ReadEncryptedPkcs8Blob(reader, ref parameters);
                return;
            }

            Debug.Fail($"Data was neither PrivateKey or EncryptedPrivateKey: {tag}");
            throw new CryptographicException($"Data was neither PrivateKey or EncryptedPrivateKey: {tag:X2}");
        }

        private static void ReadEncryptedPkcs8Blob(DerSequenceReader reader, ref RSAParameters parameters)
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

            if (algorithmOid != "1.2.840.113549.1.5.13")
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

            if (kdfOid != "1.2.840.113549.1.5.12")
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

                if (prfOid != "1.2.840.10040.4.3")
                {
                    throw new CryptographicException(prfOid);
                }
            }

            DerSequenceReader encryptionScheme = pbes2Params.ReadSequence();
            string cipherOid = encryptionScheme.ReadOidAsString();

            if (cipherOid != "1.2.840.113549.3.7")
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

                using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes("passphrase", salt, iterCount))
                using (ICryptoTransform decryptor = des3.CreateDecryptor(pbkdf2.GetBytes(keySize / 8), iv))
                {
                    byte[] encrypted = reader.ReadOctetString();
                    decrypted = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
                }
            }

            DerSequenceReader pkcs8Reader = new DerSequenceReader(decrypted);
            ReadPkcs8Blob(pkcs8Reader, ref parameters);
        }

        private static void ReadPkcs8Blob(DerSequenceReader reader, ref RSAParameters parameters)
        {
            // OneAsymmetricKey ::= SEQUENCE {
            //   version                   Version,
            //   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
            //   privateKey                PrivateKey,
            //   attributes            [0] Attributes OPTIONAL,
            //   ...,
            //   [[2: publicKey        [1] PublicKey OPTIONAL ]],
            //   ...
            // }
            //
            // PrivateKeyInfo ::= OneAsymmetricKey
            //
            // PrivateKey ::= OCTET STRING

            int version = reader.ReadInteger();

            // We understand both version 0 and 1 formats,
            // which are now known as v1 and v2, respectively.
            if (version > 1)
            {
                throw new CryptographicException();
            }

            {
                // Ensure we're reading RSA
                DerSequenceReader algorithm = reader.ReadSequence();

                string algorithmOid = algorithm.ReadOidAsString();

                if (algorithmOid != "1.2.840.113549.1.1.1")
                {
                    throw new CryptographicException(algorithmOid);
                }
            }

            byte[] privateKeyBytes = reader.ReadOctetString();
            // Because this wsa an RSA private key, the key format is PKCS#1.
            ReadPkcs1Blob(privateKeyBytes, ref parameters);

            // We don't care about the rest of the blob here, but it's expected to not exist.
        }

        private static void ReadPkcs1Blob(byte[] privateKeyBytes, ref RSAParameters parameters)
        {
            // RSAPrivateKey::= SEQUENCE {
            //    version Version,
            //    modulus           INTEGER,  --n
            //    publicExponent INTEGER,  --e
            //    privateExponent INTEGER,  --d
            //    prime1 INTEGER,  --p
            //    prime2 INTEGER,  --q
            //    exponent1 INTEGER,  --d mod(p - 1)
            //    exponent2 INTEGER,  --d mod(q - 1)
            //    coefficient INTEGER,  --(inverse of q) mod p
            //    otherPrimeInfos OtherPrimeInfos OPTIONAL
            // }
            DerSequenceReader privateKey = new DerSequenceReader(privateKeyBytes);
            int version = privateKey.ReadInteger();

            if (version != 0)
            {
                throw new CryptographicException();
            }

            parameters.Modulus = TrimPaddingByte(privateKey.ReadIntegerBytes());
            parameters.Exponent = TrimPaddingByte(privateKey.ReadIntegerBytes());

            int modulusLen = parameters.Modulus.Length;
            int halfModulus = modulusLen / 2;

            parameters.D = PadOrTrim(privateKey.ReadIntegerBytes(), modulusLen);
            parameters.P = PadOrTrim(privateKey.ReadIntegerBytes(), halfModulus);
            parameters.Q = PadOrTrim(privateKey.ReadIntegerBytes(), halfModulus);
            parameters.DP = PadOrTrim(privateKey.ReadIntegerBytes(), halfModulus);
            parameters.DQ = PadOrTrim(privateKey.ReadIntegerBytes(), halfModulus);
            parameters.InverseQ = PadOrTrim(privateKey.ReadIntegerBytes(), halfModulus);

            if (privateKey.HasData)
            {
                throw new CryptographicException();
            }
        }

        private static byte[] TrimPaddingByte(byte[] data)
        {
            if (data[0] != 0)
                return data;

            byte[] newData = new byte[data.Length - 1];
            Buffer.BlockCopy(data, 1, newData, 0, newData.Length);
            return newData;
        }

        private static byte[] PadOrTrim(byte[] data, int length)
        {
            if (data.Length == length)
                return data;

            // Need to skip the sign-padding byte.
            if (data.Length == length + 1 && data[0] == 0)
            {
                return TrimPaddingByte(data);
            }

            int offset = length - data.Length;

            byte[] newData = new byte[length];
            Buffer.BlockCopy(data, 0, newData, offset, data.Length);
            return newData;
        }
    }
}
