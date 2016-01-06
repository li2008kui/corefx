// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Internal.Cryptography
{
    internal static partial class AsymmetricFactory
    {
        private const string OpenSslAssemblyId =
            "System.Security.Cryptography.OpenSsl, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

        private const string RSATypeId = "System.Security.Cryptography.RSAOpenSsl, " + OpenSslAssemblyId;
        private const string ECDsaTypeId = "System.Security.Cryptography.ECDsaOpenSsl, " + OpenSslAssemblyId;

        private static Type LoadRSAType()
        {
            return Type.GetType(RSATypeId, true, false);
        }

        private static Type LoadECDsaType()
        {
            return Type.GetType(ECDsaTypeId, true, false);
        }

        // -----------------------------
        // ---- PAL layer ends here ----
        // -----------------------------
    }
}