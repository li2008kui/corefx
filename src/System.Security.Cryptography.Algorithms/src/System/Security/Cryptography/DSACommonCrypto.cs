// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography
{
    public partial class DSA : AsymmetricAlgorithm
    {
        public static DSA Create()
        {
            //return new DSAImplementation.DSACommonCrypto();
            throw new PlatformNotSupportedException();
        }
    }
}
