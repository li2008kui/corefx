using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace Internal.Cryptography.Pal
{
    internal static class CrlCache
    {
        public static void AddCrlForCertificate(
            X509Certificate2 cert,
            SafeX509StoreHandle store,
            X509RevocationMode revocationMode,
            ref TimeSpan remainingDownloadTime)
        {
            if (AddCachedCrl(cert, store))
            {
                return;
            }

            // Don't do any work if we're over limit or prohibited from fetching new CRLs
            if (remainingDownloadTime <= TimeSpan.Zero ||
                revocationMode != X509RevocationMode.Online)
            {
                return;
            }

            DownloadAndAddCrl(cert, store, ref remainingDownloadTime);
        }

        private static bool AddCachedCrl(X509Certificate2 cert, SafeX509StoreHandle store)
        {
            string crlFile = GetCachedCrlPath(cert);

            using (SafeBioHandle bio = Interop.libcrypto.BIO_new_file(crlFile, "rb"))
            {
                if (bio.IsInvalid)
                {
                    return false;
                }

                // X509_STORE_add_crl will increase the refcount on the CRL object, so we should still
                // dispose our copy.
                using (SafeX509CrlHandle crl = Interop.libcrypto.PEM_read_bio_X509_CRL(bio))
                {
                    if (crl.IsInvalid)
                    {
                        return false;
                    }

                    // TODO: If the CRL isn't valid for our CheckTime, return false.

                    Console.WriteLine("Adding cached CRL to X509_STORE");

                    if (!Interop.libcrypto.X509_STORE_add_crl(store, crl))
                    {
                        Console.WriteLine("This failed, and I should throw except for the one expected error");
                        //error:0B07D065:x509 certificate routines:X509_STORE_add_crl:cert already in hash table
                        //throw Interop.libcrypto.CreateOpenSslCryptographicException();
                    }

                    return true;
                }
            }
        }

        private static void DownloadAndAddCrl(
            X509Certificate2 cert,
            SafeX509StoreHandle store,
            ref TimeSpan remainingDownloadTime)
        {
            string url = GetCdpUrl(cert);

            if (url == null)
            {
                Console.WriteLine("No CDP returned");
                return;
            }

            Console.WriteLine("Downloading " + url);

            // X509_STORE_add_crl will increase the refcount on the CRL object, so we should still
            // dispose our copy.
            using (SafeX509CrlHandle crl = CertificateAssetDownloader.DownloadCrl(url, ref remainingDownloadTime))
            {
                // null is a valid return (e.g. no remainingDownloadTime)
                if (crl != null && !crl.IsInvalid)
                {
                    Console.WriteLine("Adding CRL to X509_STORE");

                    if (!Interop.libcrypto.X509_STORE_add_crl(store, crl))
                    {
                        Console.WriteLine("This failed, and I should throw except for the one expected error");
                        //error:0B07D065:x509 certificate routines:X509_STORE_add_crl:cert already in hash table
                        //throw Interop.libcrypto.CreateOpenSslCryptographicException();
                    }

                    // It doesn't matter if saving it fails
                    try
                    {
                        string crlFile = GetCachedCrlPath(cert, mkDir: true);

                        using (SafeBioHandle bio = Interop.libcrypto.BIO_new_file(crlFile, "wb"))
                        {
                            if (!bio.IsInvalid)
                            {
                                Interop.libcrypto.PEM_write_bio_X509_CRL(bio, crl);
                            }
                        }
                    }
                    catch (IOException)
                    {
                    }
                }
            }
        }
        
        private static string GetCachedCrlPath(X509Certificate2 cert, bool mkDir=false)
        {
            OpenSslX509CertificateReader pal = (OpenSslX509CertificateReader)cert.Pal;

            string crlDir = PersistedFiles.GetUserFeatureDirectory("cryptography", "crls");

            // X509_issuer_name_hash returns "unsigned long", which is marshalled as UIntPtr.
            // But it only sets 32 bits worth of data, so force it down to uint just... in case.
            ulong persistentHashLong = Interop.libcrypto.X509_issuer_name_hash(pal.SafeHandle).ToUInt64();
            uint persistentHash = unchecked((uint)persistentHashLong);

            // OpenSSL's hashed filename algorithm is the 8-character hex version of the 32-bit value
            // of X509_issuer_name_hash (or X509_subject_name_hash, depending on the context).
            string localFileName = persistentHash.ToString("x8") + ".crl";

            if (mkDir)
            {
                Directory.CreateDirectory(crlDir);
            }

            return Path.Combine(crlDir, localFileName);
        }

        private static string GetCdpUrl(X509Certificate2 cert)
        {
            byte[] crlDistributionPoints = null;

            foreach (X509Extension extension in cert.Extensions)
            {
                if (StringComparer.Ordinal.Equals(extension.Oid.Value, Oids.CrlDistributionPoints))
                {
                    // If there's an Authority Information Access extension, it might be used for
                    // looking up additional certificates for the chain.
                    crlDistributionPoints = extension.RawData;
                    break;
                }
            }

            if (crlDistributionPoints == null)
            {
                Console.WriteLine("No CDP for certificate " + cert.GetNameInfo(X509NameType.SimpleName, false));
                return null;
            }

            // CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
            //
            // DistributionPoint ::= SEQUENCE {
            //    distributionPoint       [0]     DistributionPointName OPTIONAL,
            //    reasons                 [1]     ReasonFlags OPTIONAL,
            //    cRLIssuer               [2]     GeneralNames OPTIONAL }
            //
            // DistributionPointName ::= CHOICE {
            //    fullName                [0]     GeneralNames,
            //    nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
            //
            // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
            //
            // GeneralName ::= CHOICE {
            //    otherName                       [0]     OtherName,
            //    rfc822Name                      [1]     IA5String,
            //    dNSName                         [2]     IA5String,
            //    x400Address                     [3]     ORAddress,
            //    directoryName                   [4]     Name,
            //    ediPartyName                    [5]     EDIPartyName,
            //    uniformResourceIdentifier       [6]     IA5String,
            //    iPAddress                       [7]     OCTET STRING,
            //    registeredID                    [8]     OBJECT IDENTIFIER }

            DerSequenceReader cdpSequence = new DerSequenceReader(crlDistributionPoints);

            while (cdpSequence.HasData)
            {
                const byte ContextSpecificFlag = 0x80;
                const byte ContextSpecific0 = ContextSpecificFlag;
                const byte ConstructedFlag = 0x20;
                const byte ContextSpecificConstructed0 = ContextSpecific0 | ConstructedFlag;
                const byte GeneralNameUri = ContextSpecificFlag | 0x06;

                DerSequenceReader distributionPointReader = cdpSequence.ReadSequence();
                byte tag = distributionPointReader.PeekTag();

                Console.WriteLine("First DistributionPoint element has tag {0:X}", tag);

                // Only distributionPoint is supported
                if (tag != ContextSpecificConstructed0)
                {
                    continue;
                }

                // The DistributionPointName is a CHOICE, not a SEQUENCE, but the reader is the same.
                DerSequenceReader dpNameReader = distributionPointReader.ReadSequence();
                tag = dpNameReader.PeekTag();

                Console.WriteLine("DistributionPointName element has tag {0:X}", tag);

                // Only fullName is supported,
                // nameRelativeToCRLIssuer is for LDAP-based lookup.
                if (tag != ContextSpecificConstructed0)
                {
                    continue;
                }

                DerSequenceReader fullNameReader = dpNameReader.ReadSequence();

                while (fullNameReader.HasData)
                {
                    tag = fullNameReader.PeekTag();

                    Console.WriteLine("FullName value has tag {0:X}", tag);

                    if (tag != GeneralNameUri)
                    {
                        fullNameReader.SkipValue();
                        continue;
                    }

                    string uri = fullNameReader.ReadIA5String();

                    Console.WriteLine("FullName value is {0}", uri);

                    Uri parsedUri = new Uri(uri);

                    if (!StringComparer.Ordinal.Equals(parsedUri.Scheme, "http"))
                    {
                        continue;
                    }

                    return uri;
                }
            }

            return null;
        }
    }
}