// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;

using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class Crypto
    {
        [DllImport(Libraries.CryptoNative)]
        internal static extern void EcGroupDestroy(IntPtr a);

        [DllImport(Libraries.CryptoNative)]
        internal static extern SafeEcGroupHandle EcGroupCreatePrimeCurve(
            [In] byte[] prime, int primeLen, [In] byte[] a, int aLen, [In] byte[] b, int bLen, [In] byte[] gx, int gxLen,
            [In] byte[] gy, int gyLen, [In] byte[] order, int orderLen, [In] byte[] cofactor, int cofactorLen);

        [DllImport(Libraries.CryptoNative)]
        internal static extern int EcGetKnownCurveNids([Out] int[] nids, int cNids);
    }
}
