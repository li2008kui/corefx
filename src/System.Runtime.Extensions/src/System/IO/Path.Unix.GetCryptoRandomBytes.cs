// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.Text;

namespace System.IO
{
    public static partial class Path
    {
        private static unsafe void GetCryptoRandomBytes(byte* bytes, int byteCount)
        {
            Debug.Assert(bytes != null);
            Debug.Assert(byteCount >= 0);

            if (!Interop.Crypto.GetRandomBytes(bytes, byteCount))
            {
                throw new InvalidOperationException(SR.InvalidOperation_Cryptography);
            }
        }
    }
}
