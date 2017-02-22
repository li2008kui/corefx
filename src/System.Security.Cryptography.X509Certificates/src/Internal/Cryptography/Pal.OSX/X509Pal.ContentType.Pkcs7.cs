// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Security.Cryptography;

namespace Internal.Cryptography.Pal
{
    internal sealed partial class X509Pal
    {
        private static bool ScanPkcs7(byte[] derData)
        {
            // https://tools.ietf.org/html/rfc5652
            //
            // ContentInfo ::= SEQUENCE {
            //   contentType ContentType,
            //   content[0] EXPLICIT ANY DEFINED BY contentType }
            //
            // ContentType::= OBJECT IDENTIFIER
            //
            // id-signedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
            //   us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2 }

            DerSequenceReader reader = new DerSequenceReader(derData);
            return ScanContentInfo(reader, Oids.CmsSignedData);
        }
    }
}
