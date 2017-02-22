// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Apple;
using System.Security.Cryptography.X509Certificates;

namespace Internal.Cryptography.Pal
{
    internal sealed partial class X509Pal
    {
        public static IX509Pal Instance = new AppleX509Pal();

        private X509Pal()
        {
        }

        private partial class AppleX509Pal : ManagedX509ExtensionProcessor, IX509Pal
        {
            public AsymmetricAlgorithm DecodePublicKey(Oid oid, byte[] encodedKeyValue, byte[] encodedParameters,
                ICertificatePal certificatePal)
            {
                AppleCertificatePal applePal = certificatePal as AppleCertificatePal;

                if (applePal != null)
                {
                    SafeSecKeyRefHandle key = Interop.AppleCrypto.X509GetPublicKey(applePal.CertificateHandle);

                    switch (oid.Value)
                    {
                        case Oids.RsaRsa:
                            return new RSAImplementation.RSASecurityTransforms(key);
                        case Oids.Ecc:
                            return new ECDsaImplementation.ECDsaSecurityTransforms(key);
                    }

                    key.Dispose();
                }
                else
                {
                    switch (oid.Value)
                    {
                        case Oids.RsaRsa:
                        {
                            return DecodeRsaPublicKey(encodedKeyValue);
                        }
                    }
                }

                throw new NotSupportedException(SR.NotSupported_KeyAlgorithm);
            }

            private static AsymmetricAlgorithm DecodeRsaPublicKey(byte[] encodedKeyValue)
            {
                DerSequenceReader reader = new DerSequenceReader(encodedKeyValue);
                RSAParameters rsaParameters = new RSAParameters();
                reader.ReadPkcs1PublicBlob(ref rsaParameters);

                RSA rsa = RSA.Create();
                try
                {
                    rsa.ImportParameters(rsaParameters);
                    return rsa;
                }
                catch (Exception)
                {
                    rsa.Dispose();
                    throw;
                }
            }

            public string X500DistinguishedNameDecode(byte[] encodedDistinguishedName, X500DistinguishedNameFlags flag)
            {
                return X500NameEncoder.X500DistinguishedNameDecode(encodedDistinguishedName, true, flag);
            }

            public byte[] X500DistinguishedNameEncode(string distinguishedName, X500DistinguishedNameFlags flag)
            {
                return X500NameEncoder.X500DistinguishedNameEncode(distinguishedName, flag);
            }

            public string X500DistinguishedNameFormat(byte[] encodedDistinguishedName, bool multiLine)
            {
                return X500NameEncoder.X500DistinguishedNameDecode(
                    encodedDistinguishedName,
                    true,
                    multiLine ? X500DistinguishedNameFlags.UseNewLines : X500DistinguishedNameFlags.None,
                    multiLine);
            }

            public X509ContentType GetCertContentType(byte[] rawData)
            {
                if (rawData == null || rawData.Length == 0)
                {
                    return X509ContentType.Unknown;
                }

                // All legitimate payloads start with one of the following values:
                // 0x30: DER-encoded (CONSTRUCTED SEQUENCE)
                // '-': PEM-encoded
                // 'M': Base64-encoded DER.  (PEM without the armor).

                byte[] derData = null;

                switch (rawData[0])
                {
                    case DerSequenceReader.ConstructedSequence:
                        derData = rawData;
                        break;
                    case (byte)'-':
                        derData = PemToDer(rawData);
                        break;
                    case (byte)'M':
                        derData = ConvertBase64(rawData);
                        break;
                    default:
                    {
                        // Skip over any whitespace, if appropriate.
                        // In this mode only the textual representations are valid.
                        int idx = 0;

                        while (idx < rawData.Length && char.IsWhiteSpace((char)rawData[idx]))
                        {
                            idx++;
                        }

                        if (idx < rawData.Length)
                        {
                            switch (rawData[idx])
                            {
                                case (byte)'-':
                                    derData = PemToDer(rawData);
                                    break;
                                case (byte)'M':
                                    derData = ConvertBase64(rawData);
                                    break;
                            }
                        }

                        break;
                    }
                }

                // Everything now should be in DER form, where it should start with
                // CONSTRUCTED SEQUENCE

                if (derData == null ||
                    derData.Length == 0 ||
                    derData[0] != DerSequenceReader.ConstructedSequence)
                {
                    return X509ContentType.Unknown;
                }

                try
                {
                    if (ScanPkcs12(derData))
                        return X509ContentType.Pkcs12;

                    if (ScanPkcs7(derData))
                        return X509ContentType.Pkcs7;

                    if (ScanCertificate(derData))
                        return X509ContentType.Cert;
                }
                catch (CryptographicException)
                {
                    // In the event that the blob has an invalid length value.
                    //
                    // Since all DER is DER, any exception (aside from failure to safely peek
                    // a tag before reading it) means that this isn't any known form.
                }

                return X509ContentType.Unknown;
            }

            public X509ContentType GetCertContentType(string fileName)
            {
                return GetCertContentType(System.IO.File.ReadAllBytes(fileName));
            }
        }
    }
}
