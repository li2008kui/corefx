using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace Internal.Cryptography.Pal
{
    internal class DirectoryBasedStoreProvider : IStorePal
    {
        // {thumbprint}.1.pfx to {thumbprint}.9.pfx
        private const int MaxSaveAttempts = 9; 
        private const string PfxExtension = ".pfx";
        // *.pfx ({thumbprint}.pfx or {thumbprint}.{ordinal}.pfx)
        private const string PfxWildcard = "*" + PfxExtension;
        // .*.pfx ({thumbprint}.{ordinal}.pfx)
        private const string PfxOrdinalWildcard = "." + PfxWildcard;

        private readonly string _storePath;
        private ReadOnlyCollection<X509Certificate2> _certificates;
        private FileSystemWatcher _watcher;

        private static int s_objectCount;
        private readonly int _objectCount;
        private readonly bool _readOnly;

        internal DirectoryBasedStoreProvider(string storeName, OpenFlags openFlags)
        {
            if (string.IsNullOrEmpty(storeName))
            {
                throw new CryptographicException(SR.Arg_EmptyOrNullString);
            }

            string directoryName = GetDirectoryName(storeName);
         
            _storePath = Path.Combine(
                Environment.GetEnvironmentVariable("HOME"),
                ".microsoft",
                "netfx",
                "cryptography",
                "x509stores",
                directoryName);

            if (0 != (openFlags & OpenFlags.OpenExistingOnly))
            {
                if (!Directory.Exists(_storePath))
                {
                    throw new CryptographicException(SR.Cryptography_X509_StoreNotFound);
                }
            }

            // ReadOnly is 0x00, so it is implicit unless either ReadWrite or MaxAllowed
            // was requested.
            Debug.Assert(0 == OpenFlags.ReadOnly, "OpenFlags.ReadOnly is not zero, read-only detection will not work");
            OpenFlags writeFlags = openFlags & (OpenFlags.ReadWrite | OpenFlags.MaxAllowed);

            if (writeFlags == OpenFlags.ReadOnly)
            {
                _readOnly = true;
            }

            _objectCount = Interlocked.Increment(ref s_objectCount);
        }
        
        public void Dispose()
        {
            Console.WriteLine("{0:D3} Disposing...", _objectCount);
            if (_watcher != null)
            {
                _watcher.Dispose();
                _watcher = null;
            }
        }

        public IEnumerable<X509Certificate2> Find(X509FindType findType, object findValue, bool validOnly)
        {
            return Array.Empty<X509Certificate2>();
        }

        public byte[] Export(X509ContentType contentType, string password)
        {
            // Export is for X509Certificate2Collections in their IStorePal guise,
            // if someone wanted to export whole stores they'd need to do
            // store.Certificates.Export(...), which would end up in the
            // CollectionBackedStoreProvider.
            Debug.Fail("Export was unexpected on a DirectoryBasedStore");
            throw new InvalidOperationException();
        }

        public IEnumerable<X509Certificate2> Certificates
        {
            get
            {
                // Copy the reference locally, any directory change operations
                // will cause the field to be reset to null.
                ReadOnlyCollection<X509Certificate2> certificates = _certificates;

                if (certificates == null)
                {
                    // ReadDirectory will both load _certificates and return the answer, so this call
                    // will have stable results across multiple adds/deletes happening in parallel.
                    certificates = ReadDirectory();
                    Debug.Assert(certificates != null);
                }

                return certificates;
            }
        }

        private ReadOnlyCollection<X509Certificate2> ReadDirectory()
        {
            if (!Directory.Exists(_storePath))
            {
                return new ReadOnlyCollection<X509Certificate2>(Array.Empty<X509Certificate2>());
            }

            List<X509Certificate2> certs = new List<X509Certificate2>();

            foreach (string filePath in Directory.EnumerateFiles(_storePath, PfxWildcard))
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

            if (_watcher == null)
            {
                Console.WriteLine("{0:D3} Creating a FileSystemWatcher", _objectCount);
                _watcher = new FileSystemWatcher(_storePath, PfxWildcard);
                _watcher.Changed += DirectoryChanged;
                _watcher.Created += DirectoryChanged;
                _watcher.Deleted += DirectoryChanged;
                _watcher.Renamed += DirectoryChanged;
            }

            // Start watching for change events, to know that another instance
            // has messed with the underlying store.  This keeps us aligned
            // with the Windows implementation, which opens stores with change
            // notifications.
            Console.WriteLine("{0:D3} Enabling events", _objectCount);
            _watcher.EnableRaisingEvents = true;

            ReadOnlyCollection<X509Certificate2> readOnly = certs.AsReadOnly();
            _certificates = readOnly;
            return readOnly;
        }

        public void Add(ICertificatePal certPal)
        {
            if (_readOnly)
            {
                throw new CryptographicException(SR.Cryptography_X509_StoreReadOnly);
            }

            // Save the collection to a local so it's consistent for the whole method
            ReadOnlyCollection<X509Certificate2> certificates = _certificates;
            OpenSslX509CertificateReader cert = (OpenSslX509CertificateReader)certPal;

            using (X509Certificate2 copy = new X509Certificate2(cert.DuplicateHandles()))
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
                            if (!copy.HasPrivateKey || inCollection.HasPrivateKey)
                            {
                                // If the existing store only knows about a public key, but we're
                                // adding a public+private pair, continue with the add.
                                //
                                // So, therefore, if we aren't adding a private key, or already have one,
                                // we don't need to do anything.
                                return;
                            }

                            System.Console.WriteLine("Upgrading to having a private key");
                        }
                    }
                }

                // This may well be the first time that we've added something to this store.
                Directory.CreateDirectory(_storePath);

                string thumbprint = copy.Thumbprint;
                bool findOpenSlot;

                // The odds are low that we'd have a thumbprint colission, but check anyways.
                string existingFilename = FindExistingFilename(copy, _storePath, out findOpenSlot);

                if (existingFilename != null)
                {
                    bool dataExistsAlready = false;

                    // If the file on disk is just a public key, but we're trying to add a private key,
                    // we'll want to overwrite it.
                    if (copy.HasPrivateKey)
                    {
                        try
                        {
                            using (X509Certificate2 fromFile = new X509Certificate2(existingFilename))
                            {
                                if (fromFile.HasPrivateKey)
                                {
                                    // We have a private key, the file has a private key, we're done here.
                                    System.Console.WriteLine("A file exists, which contains a private key");
                                    dataExistsAlready = true;
                                }
                                else
                                {
                                    System.Console.WriteLine("A file exists, but it is public only, adding the private key");
                                }
                            }
                        }
                        catch (CryptographicException)
                        {
                            // We can't read this file anymore, so go ahead and overwrite it.
                            System.Console.WriteLine("A file exists, but it didn't make any sense");
                        }
                    }
                    else
                    {
                        System.Console.WriteLine("A file exists, and the candidate has no private key");

                        dataExistsAlready = true;
                    }

                    if (dataExistsAlready)
                    {
                        // The file was added but our collection hasn't resynced yet.
                        // Set _certificates to null to force a resync.
                        _certificates = null;
                        return;
                    }
                }

                string destinationFilename;

                if (existingFilename != null)
                {
                    destinationFilename = existingFilename;
                }
                else if (findOpenSlot)
                {
                    destinationFilename = FindOpenSlot(thumbprint);
                }
                else
                {
                    destinationFilename = Path.Combine(_storePath, thumbprint + PfxExtension);
                }

                Console.WriteLine("{0:D3} Creating {1}", _objectCount, destinationFilename);
                File.WriteAllBytes(destinationFilename, copy.Export(X509ContentType.Pkcs12));
            }

            // Null out _certificates so the next call to get_Certificates causes a re-scan.
            _certificates = null;
        }

        public void Remove(ICertificatePal certPal)
        {
            OpenSslX509CertificateReader cert = (OpenSslX509CertificateReader)certPal;

            using (X509Certificate2 copy = new X509Certificate2(cert.DuplicateHandles()))
            {
                bool hadCandidates;
                string currentFilename = FindExistingFilename(copy, _storePath, out hadCandidates);

                if (currentFilename != null)
                {
                    if (_readOnly)
                    {
                        // Windows compatibility, the readonly check isn't done until after a match is found.
                        throw new CryptographicException(SR.Cryptography_X509_StoreReadOnly);
                    }

                    Console.WriteLine("{0:D3} Deleting {1}", _objectCount, currentFilename);
                    File.Delete(currentFilename);
                }
            }

            // Null out _certificates so the next call to get_Certificates causes a re-scan.
            _certificates = null;
        }

        private static string FindExistingFilename(X509Certificate2 cert, string storePath, out bool hadCandidates)
        {
            hadCandidates = false;

            foreach (string maybeMatch in Directory.EnumerateFiles(storePath, cert.Thumbprint + PfxWildcard))
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

        private string FindOpenSlot(string thumbprint)
        {
            // We already know that {thumbprint}.pfx is taken, so start with {thumbprint}.1.pfx

            // We need space for {thumbprint} (thumbprint.Length)
            // And ".0.pfx" (6)
            // If MaxSaveAttempts is big enough to use more than one digit, we need that space, too (MaxSaveAttempts / 10)
            StringBuilder pathBuilder = new StringBuilder(thumbprint.Length + PfxOrdinalWildcard.Length + (MaxSaveAttempts / 10));
            HashSet<string> existingFiles = new HashSet<string>(Directory.EnumerateFiles(_storePath, thumbprint + PfxOrdinalWildcard));

            for (int i = 1; i <= MaxSaveAttempts; i++)
            {
                pathBuilder.Clear();

                pathBuilder.Append(thumbprint);
                pathBuilder.Append('.');
                pathBuilder.Append(i);
                pathBuilder.Append(PfxExtension);

                string builtPath = pathBuilder.ToString();

                if (!existingFiles.Contains(builtPath))
                {
                    return Path.Combine(_storePath, builtPath);
                }
            }

            // TODO: What exception?
            throw new CryptographicException();
        }

        private void DirectoryChanged(object sender, FileSystemEventArgs e)
        {
            // Stop processing events until we read again, particularly because
            // there's nothing else we'll do until then.
            Console.WriteLine("{0:D3} Flushing cache due to {1} change on {2}", _objectCount, e.ChangeType, e.FullPath);

            // Events might end up not firing until after the object was disposed, which could cause
            // problems consistently reading _watcher; so save it to a local.
            FileSystemWatcher watcher = _watcher;

            if (watcher != null)
            {
                Console.WriteLine("{0:D3} Watcher wasn't null", _objectCount);
                watcher.EnableRaisingEvents = false;
            }
            else
            {
                Console.WriteLine("{0:D3} Weird! _watcher was null", _objectCount);
            }

            _certificates = null;
        }

        private static string GetDirectoryName(string storeName)
        {
            Debug.Assert(storeName != null);

            try
            {
                string fileName = Path.GetFileName(storeName);

                if (!StringComparer.Ordinal.Equals(storeName, fileName))
                {
                    throw new CryptographicException(SR.Format(SR.Security_InvalidValue, "storeName"));
                }
            }
            catch (IOException e)
            {
                throw new CryptographicException(e.Message, e);
            }

            return storeName.ToLowerInvariant();
        }
    }
}