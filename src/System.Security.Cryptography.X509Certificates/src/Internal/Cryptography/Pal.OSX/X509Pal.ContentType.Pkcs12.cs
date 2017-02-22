// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Security.Cryptography;

namespace Internal.Cryptography.Pal
{
    internal sealed partial class X509Pal
    {
        private static bool ScanPkcs12(byte[] derData)
        {
            // https://tools.ietf.org/html/rfc7292#appendix-D
            //
            // PFX::= SEQUENCE {
            //    version INTEGER { v3(3)}(v3,...),
            //    authSafe ContentInfo, (CONSTRUCTED SEQUENCE)
            //    macData    MacData OPTIONAL (CONSTRUCTED SEQUENCE)
            // }

            DerSequenceReader reader = new DerSequenceReader(derData);

            if (!reader.HasTag(DerSequenceReader.DerTag.Integer))
                return false;

            int dataVersion = reader.ReadInteger();

            if (dataVersion != 3)
                return false;

            if (!reader.HasTag(DerSequenceReader.ConstructedSequence))
                return false;

            DerSequenceReader contentInfo = reader.ReadSequence();

            // https://tools.ietf.org/html/rfc7292#section-4 says that this can also be
            // Oids.CmsSignedData if it's a public-key protected PFX. But we don't know
            // what to do with those, so let's just say it's Unknown.
            if (!ScanContentInfo(contentInfo, Oids.CmsData))
                return false;

            if (!reader.HasData)
                return true;

            if (!reader.HasTag(DerSequenceReader.ConstructedSequence))
                return false;

            reader.SkipValue();

            // If there's still more data it's not a PKCS#12 bundle.
            return !reader.HasData;
        }
    }
}
