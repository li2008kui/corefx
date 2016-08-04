// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Apple;

namespace Internal.Cryptography
{
    internal static partial class HashProviderDispenser
    {
        public static HashProvider CreateHashProvider(string hashAlgorithmId)
        {
            switch (hashAlgorithmId)
            {
                case HashAlgorithmNames.SHA1:
                    return new Sha1Provider();
                case HashAlgorithmNames.SHA256:
                    return new Sha256Provider();
                case HashAlgorithmNames.SHA384:
                    return new Sha384Provider();
                case HashAlgorithmNames.SHA512:
                    return new Sha512Provider();
                case HashAlgorithmNames.MD5:
                    return new Md5Provider();
            }

            throw new PlatformNotSupportedException();
        }

        public static HashProvider CreateMacProvider(string hashAlgorithmId, byte[] key)
        {
            switch (hashAlgorithmId)
            {
                case HashAlgorithmNames.SHA1:
                    return new AppleHmacProvider(Interop.AppleCrypto.PalHmacAlgorithm.HmacSha1, key);
                case HashAlgorithmNames.SHA256:
                    return new AppleHmacProvider(Interop.AppleCrypto.PalHmacAlgorithm.HmacSha256, key);
                case HashAlgorithmNames.SHA384:
                    return new AppleHmacProvider(Interop.AppleCrypto.PalHmacAlgorithm.HmacSha384, key);
                case HashAlgorithmNames.SHA512:
                    return new AppleHmacProvider(Interop.AppleCrypto.PalHmacAlgorithm.HmacSha512, key);
                case HashAlgorithmNames.MD5:
                    return new AppleHmacProvider(Interop.AppleCrypto.PalHmacAlgorithm.HmacMd5, key);
            }

            throw new PlatformNotSupportedException();
        }

        // -----------------------------
        // ---- PAL layer ends here ----
        // -----------------------------

        private class AppleHmacProvider : HashProvider
        {
            private readonly Interop.AppleCrypto.PalHmacAlgorithm _algorithm;
            private readonly byte[] _key;
            private readonly SafeHmacHandle _ctx;

            private bool _running;

            public override int HashSizeInBytes { get; }

            internal AppleHmacProvider(Interop.AppleCrypto.PalHmacAlgorithm algorithm, byte[] key)
            {
                _algorithm = algorithm;
                _key = key.CloneByteArray();
                int hashSizeInBytes = 0;
                _ctx = Interop.AppleCrypto.HmacCreate(algorithm, ref hashSizeInBytes);

                if (_ctx.IsInvalid)
                {
                    if (hashSizeInBytes < 0)
                    {
                        throw new PlatformNotSupportedException();
                    }

                    throw new CryptographicException();
                }

                HashSizeInBytes = hashSizeInBytes;
            }

            public override unsafe void AppendHashDataCore(byte[] data, int offset, int count)
            {
                if (!_running)
                {
                    SetKey();
                }

                int ret;

                fixed (byte* pData = data)
                {
                    byte* pbData = pData + offset;
                    ret = Interop.AppleCrypto.HmacUpdate(_ctx, pbData, count);
                }

                if (ret != 1)
                {
                    throw new CryptographicException();
                }
            }

            private unsafe void SetKey()
            {
                int ret;

                fixed (byte* pbKey = _key)
                {
                    ret = Interop.AppleCrypto.HmacInit(_ctx, _algorithm, pbKey, _key.Length);
                }

                if (ret != 1)
                {
                    throw new CryptographicException($"ret={ret}");
                }

                _running = true;
            }

            public override unsafe byte[] FinalizeHashAndReset()
            {
                if (!_running)
                {
                    SetKey();
                }

                byte[] output = new byte[HashSizeInBytes];
                int ret;

                fixed (byte* pbOutput = output)
                {
                    ret = Interop.AppleCrypto.HmacFinal(_ctx, pbOutput, output.Length);
                }

                if (ret != 1)
                {
                    throw new CryptographicException();
                }

                _running = false;
                return output;
            }

            public override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    _ctx?.Dispose();
                    Array.Clear(_key, 0, _key.Length);
                }
            }
        }

        private abstract class AppleDigestProvider<THandle> : HashProvider
            where THandle : SafeDigestHandle
        {
            protected readonly THandle _ctx;

            public override int HashSizeInBytes { get; }

            protected AppleDigestProvider()
            {
                int hashSizeInBytes;
                _ctx = Create(out hashSizeInBytes);

                if (_ctx.IsInvalid)
                    throw new CryptographicException();

                HashSizeInBytes = hashSizeInBytes;
            }

            protected abstract THandle Create(out int hashSizeInBytes);
            protected abstract unsafe int AppendData(byte* pbData, int cbData);
            protected abstract unsafe int Final(byte* pbOutput, int cbOutput);

            public override unsafe void AppendHashDataCore(byte[] data, int offset, int count)
            {
                int ret;

                fixed (byte* pData = data)
                {
                    byte* pbData = pData + offset;
                    ret = AppendData(pbData, count);
                }

                if (ret != 1)
                {
                    throw new CryptographicException($"ret={ret}");
                }
            }

            public override unsafe byte[] FinalizeHashAndReset()
            {
                byte[] hash = new byte[HashSizeInBytes];
                int ret;

                fixed (byte* pHash = hash)
                {
                    ret = Final(pHash, hash.Length);
                }

                if (ret != 1)
                {
                    throw new CryptographicException($"ret={ret}");
                }

                return hash;
            }

            public override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    _ctx?.Dispose();
                }
            }
        }

        private class Sha1Provider : AppleDigestProvider<SafeSha1DigestHandle>
        {
            protected override SafeSha1DigestHandle Create(out int hashSizeInBytes)
            {
                return Interop.AppleCrypto.Sha1Create(out hashSizeInBytes);
            }

            protected override unsafe int AppendData(byte* pbData, int cbData)
            {
                return Interop.AppleCrypto.Sha1Update(_ctx, pbData, cbData);
            }

            protected override unsafe int Final(byte* pbOutput, int cbOutput)
            {
                return Interop.AppleCrypto.Sha1Final(_ctx, pbOutput, cbOutput);
            }
        }

        private class Sha256Provider : AppleDigestProvider<SafeSha256DigestHandle>
        {
            protected override SafeSha256DigestHandle Create(out int hashSizeInBytes)
            {
                return Interop.AppleCrypto.Sha256Create(out hashSizeInBytes);
            }

            protected override unsafe int AppendData(byte* pbData, int cbData)
            {
                return Interop.AppleCrypto.Sha256Update(_ctx, pbData, cbData);
            }

            protected override unsafe int Final(byte* pbOutput, int cbOutput)
            {
                return Interop.AppleCrypto.Sha256Final(_ctx, pbOutput, cbOutput);
            }
        }

        private class Sha384Provider : AppleDigestProvider<SafeSha384DigestHandle>
        {
            protected override SafeSha384DigestHandle Create(out int hashSizeInBytes)
            {
                return Interop.AppleCrypto.Sha384Create(out hashSizeInBytes);
            }

            protected override unsafe int AppendData(byte* pbData, int cbData)
            {
                return Interop.AppleCrypto.Sha384Update(_ctx, pbData, cbData);
            }

            protected override unsafe int Final(byte* pbOutput, int cbOutput)
            {
                return Interop.AppleCrypto.Sha384Final(_ctx, pbOutput, cbOutput);
            }
        }

        private class Sha512Provider : AppleDigestProvider<SafeSha512DigestHandle>
        {
            protected override SafeSha512DigestHandle Create(out int hashSizeInBytes)
            {
                return Interop.AppleCrypto.Sha512Create(out hashSizeInBytes);
            }

            protected override unsafe int AppendData(byte* pbData, int cbData)
            {
                return Interop.AppleCrypto.Sha512Update(_ctx, pbData, cbData);
            }

            protected override unsafe int Final(byte* pbOutput, int cbOutput)
            {
                return Interop.AppleCrypto.Sha512Final(_ctx, pbOutput, cbOutput);
            }
        }

        private class Md5Provider : AppleDigestProvider<SafeMd5DigestHandle>
        {
            protected override SafeMd5DigestHandle Create(out int hashSizeInBytes)
            {
                return Interop.AppleCrypto.Md5Create(out hashSizeInBytes);
            }

            protected override unsafe int AppendData(byte* pbData, int cbData)
            {
                return Interop.AppleCrypto.Md5Update(_ctx, pbData, cbData);
            }

            protected override unsafe int Final(byte* pbOutput, int cbOutput)
            {
                return Interop.AppleCrypto.Md5Final(_ctx, pbOutput, cbOutput);
            }
        }
    }
}
