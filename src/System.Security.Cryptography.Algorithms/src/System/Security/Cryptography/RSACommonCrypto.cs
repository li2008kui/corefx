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
                SafeCreateHandle cfData;
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

                if (ret == 1)
                {
                    throw new CryptographicException($"Got valid data: {!cfData.IsInvalid}");
                }
                else if (ret == 0)
                {
                    // TODO: Is there a better OSStatus lookup?
                    throw Interop.AppleCrypto.CreateExceptionForCCError(osStatus, "OSStatus");
                }

                Debug.Fail($"RsaExportKey returned {ret}");
                throw new CryptographicException($"ret is {ret}");
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
    }
}
