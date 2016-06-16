// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Security;
using System.Runtime.InteropServices;

namespace Microsoft.Win32.SafeHandles
{
    [SecurityCritical]
    internal sealed class SafeX509Handle : DebugSafeHandle
    {
        internal static readonly SafeX509Handle InvalidHandle = new SafeX509Handle();

        private static readonly bool s_includeContents =
            !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("SAFEX509HANDLE_CONTENTS"));

        [DllImport("libcrypto")]
        private static extern int X509_print_ex(SafeBioHandle bp, IntPtr x509, int nmflag, int cflag);

        private SafeX509Handle() : 
            base(IntPtr.Zero, ownsHandle: true)
        {
        }

        protected override void Dispose(bool disposing)
        {
            if (!disposing && s_includeContents)
            {
                if (handle == IntPtr.Zero)
                {
                    SafeBioHandle.BIO_printf(SafeBioHandle.StdOut, "Finalized NULL certificate!\n");
                }
                else
                {
                    SafeBioHandle.BIO_printf(SafeBioHandle.StdOut, "Finalized certificate:\n");
                    X509_print_ex(SafeBioHandle.StdOut, handle, 0, 0);
                }
            }

            base.Dispose(disposing);
        }

        [SecurityCritical]
        protected override bool ReleaseHandle()
        {
            Interop.Crypto.X509Destroy(handle);
            SetHandle(IntPtr.Zero);
            return true;
        }

        public override bool IsInvalid
        {
            [SecurityCritical]
            get { return handle == IntPtr.Zero; }
        }
    }

    internal sealed class SafeX509CrlHandle : DebugSafeHandle
    {
        private SafeX509CrlHandle() :
            base(IntPtr.Zero, ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle()
        {
            Interop.Crypto.X509CrlDestroy(handle);
            SetHandle(IntPtr.Zero);
            return true;
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }
    }

    [SecurityCritical]
    internal sealed class SafeX509StoreHandle : DebugSafeHandle
    {
        private SafeX509StoreHandle() :
            base(IntPtr.Zero, ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle()
        {
            Interop.Crypto.X509StoreDestory(handle);
            SetHandle(IntPtr.Zero);
            return true;
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }
    }
}
