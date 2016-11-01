// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Apple;
using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class AppleCrypto
    {
        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_EccGenerateKey")]
        internal static extern int EccGenerateKey(
            int keySizeInBits,
            out SafeSecKeyRefHandle pPublicKey,
            out SafeSecKeyRefHandle pPrivateKey,
            out int pOSStatus);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_EccImportEphemeralKey")]
        internal static extern int EccImportEphemeralKey(
            byte[] keyBlob,
            int cbkeyBlob,
            bool isPrivateKey,
            out SafeSecKeyRefHandle key,
            out int pOSStatus);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_EcdsaSign")]
        private static extern int EcdsaSign(
            SafeSecKeyRefHandle key,
            byte[] pbDataHash,
            int cbDataHash,
            out SafeCFDataHandle pSignatureOut,
            out SafeCreateHandle pErrorOut);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_EcdsaVerify")]
        private static extern int EcdsaVerify(
            SafeSecKeyRefHandle key,
            byte[] pbDataHash,
            int cbDataHash,
            byte[] pbSignature,
            int cbSignature,
            out SafeCreateHandle pErrorOut);

        internal static byte[] ECDsaSign(SafeSecKeyRefHandle key, byte[] hash)
        {
            SafeCFDataHandle signature;
            SafeCreateHandle error;
            int ret = EcdsaSign(key, hash, hash.Length, out signature, out error);

            using (error)
            using (signature)
            {
                if (ret == 1)
                {
                    return CoreFoundation.CFGetData(signature);
                }

                if (ret == -2)
                {
                    Debug.Assert(!error.IsInvalid, "Native layer indicated error object was populated");
                    // TODO: Throw a CFErrorRef-based exception
                    throw new CryptographicException("A CFError was produced");
                }

                Debug.Fail("RsaVerify returned {ret}");
                throw new CryptographicException();
            }
        }

        internal static bool ECDsaVerify(
            SafeSecKeyRefHandle key,
            byte[] hash,
            byte[] signature)
        {
            SafeCreateHandle error;
            int ret = EcdsaVerify(key, hash, hash.Length, signature, signature.Length, out error);

            using (error)
            {
                if (ret == 1)
                {
                    return true;
                }

                if (ret == 0)
                {
                    return false;
                }

                if (ret == -2)
                {
                    Debug.Assert(!error.IsInvalid, "Native layer indicated error object was populated");
                    // TODO: Throw a CFErrorRef-based exception
                    throw new CryptographicException("A CFError was produced");
                }

                Debug.Fail("RsaVerify returned {ret}");
                throw new CryptographicException();
            }
        }
    }
}