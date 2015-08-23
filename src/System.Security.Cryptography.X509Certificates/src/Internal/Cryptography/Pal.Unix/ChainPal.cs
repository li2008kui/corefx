// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Internal.Cryptography.Pal
{
    internal sealed partial class ChainPal
    {
        public static bool ReleaseSafeX509ChainHandle(IntPtr handle)
        {
            return true;
        }

        public static IChainPal BuildChain(
            bool useMachineContext,
            ICertificatePal cert,
            X509Certificate2Collection extraStore,
            OidCollection applicationPolicy,
            OidCollection certificatePolicy,
            X509RevocationMode revocationMode,
            X509RevocationFlag revocationFlag,
            DateTime verificationTime,
            TimeSpan timeout)
        {
            CheckRevocationMode(revocationMode);

            X509Certificate2 leaf = new X509Certificate2(cert.Handle);
            List<X509Certificate2> downloaded = new List<X509Certificate2>();

            List<X509Certificate2> candidates =
                OpenSslX509ChainProcessor.FindCandidates(leaf, extraStore, downloaded);

            IChainPal chain = OpenSslX509ChainProcessor.BuildChain(
                leaf,
                candidates,
                downloaded,
                applicationPolicy,
                certificatePolicy,
                verificationTime);

            Console.WriteLine(
                "chain.ChainStatus.Length == {0} && downloaded.Count == {1}",
                chain.ChainStatus.Length,
                downloaded.Count);

            if (chain.ChainStatus.Length == 0 && downloaded.Count > 0)
            {
                SaveIntermediateCertificates(downloaded);
            }

            return chain;
        }

        private static void CheckRevocationMode(X509RevocationMode revocationMode)
        {
            if (revocationMode != X509RevocationMode.NoCheck)
            {
                // TODO (#2203): Add support for revocation once networking is ready.
                throw new NotImplementedException(SR.WorkInProgress);
            }
        }

        private static void SaveIntermediateCertificates(List<X509Certificate2> downloaded)
        {
            using (var userIntermediate = new X509Store(StoreName.CertificateAuthority, StoreLocation.CurrentUser))
            {
                try
                {
                    userIntermediate.Open(OpenFlags.ReadWrite);
                }
                catch (CryptographicException)
                {
                    // Saving is opportunistic, just ignore failures
                    return;
                }

                for (int i = 0; i < downloaded.Count; i++)
                {
                    try
                    {
                        Console.WriteLine("Saving intermediate certificate " + downloaded[i].GetNameInfo(X509NameType.SimpleName, false));
                        userIntermediate.Add(downloaded[i]);
                    }
                    catch (CryptographicException)
                    {
                        // Saving is opportunistic, just ignore failures
                    }
                    catch (IOException)
                    {
                        // Saving is opportunistic, just ignore failures
                    }
                }
            }
        }
    }
}
