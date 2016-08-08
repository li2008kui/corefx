// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Apple;

internal static partial class Interop
{
    internal static partial class AppleCrypto
    {
        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_DigestFree")]
        internal static extern void DigestFree(IntPtr handle);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_Sha1Create")]
        internal static extern SafeSha1DigestHandle Sha1Create(out int cbDigest);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_Sha1Update")]
        internal static extern unsafe int Sha1Update(SafeSha1DigestHandle ctx, byte* pbData, int cbData);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_Sha1Final")]
        internal static extern unsafe int Sha1Final(SafeSha1DigestHandle ctx, byte* pbOutput, int cbOutput);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_Sha256Create")]
        internal static extern SafeSha256DigestHandle Sha256Create(out int cbDigest);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_Sha256Update")]
        internal static extern unsafe int Sha256Update(SafeSha256DigestHandle ctx, byte* pbData, int cbData);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_Sha256Final")]
        internal static extern unsafe int Sha256Final(SafeSha256DigestHandle ctx, byte* pbOutput, int cbOutput);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_Sha384Create")]
        internal static extern SafeSha384DigestHandle Sha384Create(out int cbDigest);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_Sha384Update")]
        internal static extern unsafe int Sha384Update(SafeSha384DigestHandle ctx, byte* pbData, int cbData);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_Sha384Final")]
        internal static extern unsafe int Sha384Final(SafeSha384DigestHandle ctx, byte* pbOutput, int cbOutput);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_Sha512Create")]
        internal static extern SafeSha512DigestHandle Sha512Create(out int cbDigest);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_Sha512Update")]
        internal static extern unsafe int Sha512Update(SafeSha512DigestHandle ctx, byte* pbData, int cbData);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_Sha512Final")]
        internal static extern unsafe int Sha512Final(SafeSha512DigestHandle ctx, byte* pbOutput, int cbOutput);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_Md5Create")]
        internal static extern SafeMd5DigestHandle Md5Create(out int cbDigest);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_Md5Update")]
        internal static extern unsafe int Md5Update(SafeMd5DigestHandle ctx, byte* pbData, int cbData);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_Md5Final")]
        internal static extern unsafe int Md5Final(SafeMd5DigestHandle ctx, byte* pbOutput, int cbOutput);
    }
}

namespace System.Security.Cryptography.Apple
{
    internal abstract class SafeDigestHandle : SafeHandle
    {
        internal SafeDigestHandle(IntPtr handleValue, bool ownsHandle)
            : base(handleValue, ownsHandle)
        {
        }

        protected override bool ReleaseHandle()
        {
            Interop.AppleCrypto.DigestFree(handle);
            SetHandle(IntPtr.Zero);
            return true;
        }

        public override bool IsInvalid => handle == IntPtr.Zero;
    }

    internal class SafeSha1DigestHandle : SafeDigestHandle
    {
        internal SafeSha1DigestHandle()
            : base(IntPtr.Zero, ownsHandle: true)
        {
        }
    }

    internal class SafeSha256DigestHandle : SafeDigestHandle
    {
        internal SafeSha256DigestHandle()
            : base(IntPtr.Zero, ownsHandle: true)
        {
        }
    }

    internal class SafeSha384DigestHandle : SafeDigestHandle
    {
        internal SafeSha384DigestHandle()
            : base(IntPtr.Zero, ownsHandle: true)
        {
        }
    }

    internal class SafeSha512DigestHandle : SafeDigestHandle
    {
        internal SafeSha512DigestHandle()
            : base(IntPtr.Zero, ownsHandle: true)
        {
        }
    }

    internal class SafeMd5DigestHandle : SafeDigestHandle
    {
        internal SafeMd5DigestHandle()
            : base(IntPtr.Zero, ownsHandle: true)
        {
        }
    }
}