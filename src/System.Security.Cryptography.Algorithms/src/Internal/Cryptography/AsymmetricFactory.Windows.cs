// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Internal.Cryptography
{
    internal static partial class AsymmetricFactory
    {
        private const string CngAssemblyId =
            "System.Security.Cryptography.Cng, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

        private const string RSATypeId = "System.Security.Cryptography.RSACng, " + CngAssemblyId;
        private const string ECDsaTypeId = "System.Security.Cryptography.ECDsaCng, " + CngAssemblyId;

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