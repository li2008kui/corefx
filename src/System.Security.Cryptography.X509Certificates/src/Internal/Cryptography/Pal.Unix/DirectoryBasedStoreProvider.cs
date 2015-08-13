using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Internal.Cryptography.Pal
{
    internal class DirectoryBasedStoreProvider : IStorePal
    {
        private const int MaxSaveAttempts = 9; // {thumbprint}.1.pem to {thumbprint}.9.pem

        private readonly string _storePath;
        private List<X509Certificate2> _certificates;

        internal DirectoryBasedStoreProvider(string storeName)
        {
            string directoryName;

            storeName = storeName == null ? null : storeName.ToUpperInvariant();

            switch (storeName)
            {
                case "MY":
                    directoryName = "my";
                    break;
                default:
                    // TODO: What exception for "store not supported"?
                    throw new CryptographicException();
            }

            _storePath = Path.Combine(
                Environment.GetEnvironmentVariable("HOME"),
                ".microsoft",
                "netfx",
                "cryptography",
                "x509stores",
                directoryName);
        }

        public void Dispose()
        {
        }

        public IEnumerable<X509Certificate2> Find(X509FindType findType, object findValue, bool validOnly)
        {
            throw new NotImplementedException();
        }

        public byte[] Export(X509ContentType contentType, string password)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<X509Certificate2> Certificates
        {
            get
            {
                // Copy the reference locally, any directory change operations
                // will cause the field to be reset to null.
                List<X509Certificate2> certificates = _certificates;

                if (certificates == null)
                {
                    // ReadDirectory will both load _certificates and return the answer, so this call
                    // will have stable results across multiple adds/deletes happening in parallel.
                    certificates = ReadDirectory();
                    Debug.Assert(certificates != null);
                }

                foreach (X509Certificate2 cert in certificates)
                {
                    // TODO: Should this return new X509Certificate2(cert.Handle) so that we can dispose our copies?
                    yield return cert;
                }
            }
        }

        private List<X509Certificate2> ReadDirectory()
        {
            if (!Directory.Exists(_storePath))
            {
                return new List<X509Certificate2>(0);
            }

            List<X509Certificate2> certs = new List<X509Certificate2>();

            foreach (string filePath in Directory.EnumerateFiles(_storePath))
            {
                X509Certificate2 cert;

                try
                {
                    cert = new X509Certificate2(filePath);
                }
                catch (CryptographicException)
                {
                    // The file wasn't a certificate, move on to the next one.
                    continue;
                }

                certs.Add(cert);
            }

            _certificates = certs;
            return certs;
        }

        public void Add(ICertificatePal cert)
        {
            // Save the collection to a local so it's consistent for the whole method
            List<X509Certificate2> certificates = _certificates;

            if (cert.HasPrivateKey)
            {
                throw new NotSupportedException("Eep, a private key!");
            }

            using (X509Certificate2 copy = new X509Certificate2(cert.Handle))
            {
                // certificates will be null if anything has changed since the last call to
                // get_Certificates; including Add being called without get_Certificates being
                // called at all.
                if (certificates != null)
                {
                    foreach (X509Certificate2 inCollection in certificates)
                    {
                        if (inCollection.Equals(copy))
                        {
                            return;
                        }
                    }
                }

                // This may well be the first time that we've added something to this store.
                Directory.CreateDirectory(_storePath);

                string thumbprint = copy.Thumbprint;
                bool findOpenSlot = false;

                // The odds are low that we'd have a thumbprint colission, but check anyways.
                string existingFilename = FindExistingFilename(copy, _storePath, out findOpenSlot);

                if (existingFilename != null)
                {
                    // The file was added but our collection hasn't resynced yet.
                    // Set _certificates to null to force a resync.
                    _certificates = null;
                    return;
                }

                string destinationFilename;

                if (findOpenSlot)
                {
                    destinationFilename = FindOpenSlot(thumbprint);
                }
                else
                {
                    destinationFilename = Path.Combine(_storePath, thumbprint + ".pem");
                }

                WritePem(copy.RawData, destinationFilename);
            }

            // Null out _certificates so the next call to get_Certificates causes a re-scan.
            _certificates = null;
        }

        private static string FindExistingFilename(X509Certificate2 cert, string storePath, out bool hadCandidates)
        {
            hadCandidates = false;

            foreach (string maybeMatch in Directory.EnumerateFiles(storePath, cert.Thumbprint + "*.pem"))
            {
                hadCandidates = true;

                System.Console.WriteLine("Checking '{0}' for match...", maybeMatch);

                try
                {
                    using (X509Certificate2 candidate = new X509Certificate2(maybeMatch))
                    {
                        if (candidate.Equals(cert))
                        {
                            return maybeMatch;
                        }
                    }
                }
                catch (CryptographicException)
                {
                    // Contents weren't interpretable as a certificate, so it's not a match.
                }
            }

            return null;
        }

        private static void WritePem(byte[] rawData, string destinationFilename)
        {
            // Convert's Base64 with newline formatting wraps at 72 characters, PEM wraps at 64.
            const int PemBase64CharsPerLine = 64;

            // Base64 encoding does a 3=>4 expansion, but anything left over that was less
            // than 3 bytes still needs 4 characters to encode it.
            int expectedCharCount = rawData.Length / 3 * 4;

            if (rawData.Length % 3 != 0)
            {
                expectedCharCount += 4;
            }

            char[] base64 = new char[expectedCharCount];
            int base64CharCount = Convert.ToBase64CharArray(rawData, 0, rawData.Length, base64, 0);

            Debug.Assert(base64CharCount == base64.Length);

            using (FileStream fileStream = File.Create(destinationFilename))
            using (StreamWriter writer = new StreamWriter(fileStream, Encoding.ASCII))
            {
                writer.WriteLine("-----BEGIN CERTIFICATE-----");

                int idx = 0;

                while (idx < base64CharCount)
                {
                    int charsRemaining = base64CharCount - idx;
                    int charsThisLine = Math.Min(charsRemaining, PemBase64CharsPerLine);

                    writer.WriteLine(base64, idx, charsThisLine);

                    idx += charsThisLine;
                }

                writer.WriteLine("-----END CERTIFICATE-----");
            }
        }

        private string FindOpenSlot(string thumbprint)
        {
            // We already know that {thumbprint}.pem is taken, so start with {thumbprint}.1.pem

            // We need space for {thumbprint} (thumbprint.Length)
            // And ".0.pem" (6)
            // If MaxSaveAttempts is big enough to use more than one digit, we need that space, too (MaxSaveAttempts / 10)
            StringBuilder pathBuilder = new StringBuilder(thumbprint.Length + 6 + (MaxSaveAttempts / 10));
            HashSet<string> existingFiles = new HashSet<string>(Directory.EnumerateFiles(_storePath, thumbprint + ".*.pem"));

            for (int i = 1; i <= MaxSaveAttempts; i++)
            {
                pathBuilder.Clear();

                pathBuilder.Append(thumbprint);
                pathBuilder.Append('.');
                pathBuilder.Append(i);
                pathBuilder.Append(".pem");

                string builtPath = pathBuilder.ToString();

                if (!existingFiles.Contains(builtPath))
                {
                    return Path.Combine(_storePath, builtPath);
                }
            }

            // TODO: What exception?
            throw new CryptographicException();
        }

        public void Remove(ICertificatePal cert)
        {
            throw new NotImplementedException();
        }
    }
}