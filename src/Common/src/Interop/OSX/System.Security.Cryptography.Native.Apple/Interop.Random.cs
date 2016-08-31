// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class AppleCrypto
    {
        [DllImport(Libraries.AppleCryptoNative, EntryPoint="AppleCryptoNative_GetRandomBytes")]
        internal static unsafe extern int GetRandomBytes(byte* buf, int num, out int errorCode);
    }
}
