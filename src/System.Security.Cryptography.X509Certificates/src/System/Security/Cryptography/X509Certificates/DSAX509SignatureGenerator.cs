// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using Internal.Cryptography;

namespace System.Security.Cryptography.X509Certificates
{
    internal sealed class DSAX509SignatureGenerator : X509SignatureGenerator
    {
        private readonly DSA _key;

        public DSAX509SignatureGenerator(DSA key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            _key = key;
        }

        public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm)
        {
            string oid = null;

            if (hashAlgorithm == HashAlgorithmName.SHA1)
                oid = Oids.DsaSha1;
            else if (hashAlgorithm == HashAlgorithmName.SHA256)
                oid = Oids.DsaSha256;

            // No OID exists for SHA384 or SHA512.

            if (oid == null)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(hashAlgorithm),
                    hashAlgorithm,
                    SR.Format(SR.Cryptography_UnknownHashAlgorithm, hashAlgorithm.Name));
            }

            return DerEncoder.ConstructSequence(DerEncoder.SegmentedEncodeOid(oid));
        }

        public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm)
        {
            byte[] ieeeFormat = _key.SignData(data, hashAlgorithm);

            Debug.Assert(ieeeFormat.Length % 2 == 0);
            int segmentLength = ieeeFormat.Length / 2;

            return DerEncoder.ConstructSequence(
                DerEncoder.SegmentedEncodeUnsignedInteger(ieeeFormat, 0, segmentLength),
                DerEncoder.SegmentedEncodeUnsignedInteger(ieeeFormat, segmentLength, segmentLength));
        }

        protected override PublicKey BuildPublicKey()
        {
            Oid oid = new Oid(Oids.DsaDsa);

            DSAParameters dsaParameters = _key.ExportParameters(false);

            // Dss-Parms ::= SEQUENCE {
            //   p INTEGER,
            //   q INTEGER,
            //   g INTEGER
            // }
            byte[] algParameters = DerEncoder.ConstructSequence(
                DerEncoder.SegmentedEncodeUnsignedInteger(dsaParameters.P),
                DerEncoder.SegmentedEncodeUnsignedInteger(dsaParameters.Q),
                DerEncoder.SegmentedEncodeUnsignedInteger(dsaParameters.G));

            byte[] keyValue = DerEncoder.EncodeUnsignedInteger(dsaParameters.Y);

            return new PublicKey(
                oid,
                new AsnEncodedData(oid, algParameters),
                new AsnEncodedData(oid, keyValue));
        }
    }
}
