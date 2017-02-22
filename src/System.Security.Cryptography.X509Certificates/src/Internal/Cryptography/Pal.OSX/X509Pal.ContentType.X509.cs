// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Security.Cryptography;

namespace Internal.Cryptography.Pal
{
    internal sealed partial class X509Pal
    {
        private static bool ScanCertificate(byte[] derData)
        {
            // This could be written as
            // try { new CertificateData(derData); return true; } catch { return false; }
            // But that would mean that we will only attempt to open certificates that we know
            // we can read.
            //
            // Much better would be that we scan it for candidacy, let the native function open it,
            // and THEN if we fail to read it we know we have a mismatch with the native layer.
            //
            // Admittedly, much much better would be if SecItemImport didn't mis-identify content
            // types, so we didn't need to do this at all.

            // https://tools.ietf.org/html/rfc3280#section-4
            // Certificate  ::=  SEQUENCE  {
            //   tbsCertificate       TBSCertificate,
            //   signatureAlgorithm   AlgorithmIdentifier,
            //   signatureValue       BIT STRING  }
            //
            // TBSCertificate  ::=  SEQUENCE  {
            //   version         [0]  EXPLICIT Version DEFAULT v1,
            //   serialNumber         CertificateSerialNumber,
            //   signature            AlgorithmIdentifier,
            //   issuer               Name,
            //   validity             Validity,
            //   subject              Name,
            //   subjectPublicKeyInfo SubjectPublicKeyInfo,
            //   issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
            //             -- If present, version MUST be v2 or v3
            //   subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
            //             -- If present, version MUST be v2 or v3
            //   extensions      [3]  EXPLICIT Extensions OPTIONAL
            //             -- If present, version MUST be v3
            // }
            //
            // Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
            // CertificateSerialNumber  ::=  INTEGER

            DerSequenceReader reader = new DerSequenceReader(derData);

            if (!reader.HasTag(DerSequenceReader.ConstructedSequence))
                return false;

            string tbsSignatureOid = null;
            byte[] tbsSignatureParams = null;

            if (!ScanTbsCertificate(reader.ReadSequence(), ref tbsSignatureOid, ref tbsSignatureParams))
                return false;

            if (!reader.HasTag(DerSequenceReader.ConstructedSequence))
                return false;

            // ScanAlgorithmIdentifier
            if (!ScanSignatureAlgorithm(reader.ReadSequence(), tbsSignatureOid, tbsSignatureParams))
                return false;

            if (!reader.HasTag(DerSequenceReader.DerTag.BitString))
                return false;

            reader.SkipValue();

            // If there's nothing left, it's probably a certificate.
            return !reader.HasData;
        }

        private static bool ScanTbsCertificate(
            DerSequenceReader tbsReader,
            ref string tbsSignatureOid,
            ref byte[] tbsSignatureParams)
        {
            if (tbsReader.HasTag(DerSequenceReader.ContextSpecificConstructedTag0))
            {
                DerSequenceReader versionReader = tbsReader.ReadSequence();

                if (!versionReader.HasTag(DerSequenceReader.DerTag.Integer))
                {
                    return false;
                }

                versionReader.SkipValue();

                if (versionReader.HasData)
                    return false;
            }

            // serialNumber
            if (!tbsReader.HasTag(DerSequenceReader.DerTag.Integer))
                return false;

            tbsReader.SkipValue();

            // signature
            if (!tbsReader.HasTag(DerSequenceReader.ConstructedSequence))
                return false;

            // AlgorithmIdentifier::= SEQUENCE  {
            //    algorithm OBJECT IDENTIFIER,
            //    parameters ANY DEFINED BY algorithm OPTIONAL  }
            DerSequenceReader tbsSignatureAlgorithm = tbsReader.ReadSequence();

            if (!tbsSignatureAlgorithm.HasTag(DerSequenceReader.DerTag.ObjectIdentifier))
                return false;

            tbsSignatureOid = tbsSignatureAlgorithm.ReadOidAsString();

            if (tbsSignatureAlgorithm.HasData)
            {
                tbsSignatureParams = tbsSignatureAlgorithm.ReadNextEncodedValue();
            }

            if (tbsSignatureAlgorithm.HasData)
                return false;

            // issuer
            if (!tbsReader.HasTag(DerSequenceReader.ConstructedSequence))
                return false;

            tbsReader.SkipValue();

            // validity
            if (!tbsReader.HasTag(DerSequenceReader.ConstructedSequence))
                return false;

            tbsReader.SkipValue();

            // subject
            if (!tbsReader.HasTag(DerSequenceReader.ConstructedSequence))
                return false;

            tbsReader.SkipValue();

            // subjectPublicKeyInfo
            if (!tbsReader.HasTag(DerSequenceReader.ConstructedSequence))
                return false;

            // Be lax about new data beyond here.
            // Strictness will be enforced at load time by the native library.
            return true;
        }

        private static bool ScanSignatureAlgorithm(
            DerSequenceReader signatureAlgorithmReader,
            string tbsSignatureOid,
            byte[] tbsSignatureParams)
        {
            if (!signatureAlgorithmReader.HasTag(DerSequenceReader.DerTag.ObjectIdentifier))
                return false;

            string signatureAlgorithm = signatureAlgorithmReader.ReadOidAsString();

            // This field MUST contain the same algorithm identifier as the
            // signature field in the sequence tbsCertificate
            // (per https://tools.ietf.org/html/rfc3280#section-4.1.1.2)

            if (tbsSignatureOid != signatureAlgorithm)
                return false;

            byte[] encodedParams = null;

            if (signatureAlgorithmReader.HasData)
            {
                encodedParams = signatureAlgorithmReader.ReadNextEncodedValue();
            }

            if (!AreAlgorithmParametersEqual(tbsSignatureParams, encodedParams))
                return false;

            // If there's nothing left we're done.
            return !signatureAlgorithmReader.HasData;
        }

        private static bool AreAlgorithmParametersEqual(byte[] tbsParams, byte[] sigParams)
        {
            if (sigParams == null && tbsParams == null)
                return true;

            if (sigParams == null)
            {
                sigParams = tbsParams;
                tbsParams = null;
            }

            if (tbsParams == null)
            {
                return
                    sigParams.Length == 2 &&
                    sigParams[0] == (byte)DerSequenceReader.DerTag.Null &&
                    sigParams[1] == 0;
            }

            if (tbsParams.Length != sigParams.Length)
                return false;

            for (int i = 0; i < tbsParams.Length; i++)
            {
                if (tbsParams[i] != sigParams[i])
                    return false;
            }

            return true;
        }
    }
}
