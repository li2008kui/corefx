// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Runtime.InteropServices;
using System.Security;

namespace Microsoft.Win32.SafeHandles
{
    public abstract class DebugSafeHandle : SafeHandle
    {
        private static readonly bool s_includeStackTrace =
            !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DEBUGSAFEHANDLE_STACKTRACE"));

        private static int _count;
        private string _stack;

        [DllImport("libc")]
        private static extern int printf(string format, string arg);

        internal DebugSafeHandle(IntPtr invalidHandle, bool ownsHandle) : base(invalidHandle, ownsHandle)
        {
            _stack = s_includeStackTrace ?
                Environment.StackTrace :
                "--set DEBUGSAFEHANDLE_STACKTRACE for stack traces--";
        }

        protected override void Dispose(bool disposing)
        {
            if (!disposing)
            {
                int count = System.Threading.Interlocked.Increment(ref _count);
                printf("%s\n", $"Finalizing ({count}) {GetType().FullName}{Environment.NewLine}{_stack}");
            }
            base.Dispose(disposing);
        }
    }

    [SecurityCritical]
    internal sealed class SafeAsn1ObjectHandle : DebugSafeHandle
    {
        private SafeAsn1ObjectHandle() :
            base(IntPtr.Zero, ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle()
        {
            Interop.Crypto.Asn1ObjectFree(handle);
            SetHandle(IntPtr.Zero);
            return true;
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }
    }

    [SecurityCritical]
    internal sealed class SafeAsn1BitStringHandle : DebugSafeHandle
    {
        private SafeAsn1BitStringHandle() :
            base(IntPtr.Zero, ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle()
        {
            Interop.Crypto.Asn1BitStringFree(handle);
            SetHandle(IntPtr.Zero);
            return true;
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }
    }

    [SecurityCritical]
    internal sealed class SafeAsn1OctetStringHandle : DebugSafeHandle
    {
        private SafeAsn1OctetStringHandle() :
            base(IntPtr.Zero, ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle()
        {
            Interop.Crypto.Asn1OctetStringFree(handle);
            SetHandle(IntPtr.Zero);
            return true;
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }
    }

    [SecurityCritical]
    internal sealed class SafeAsn1StringHandle : DebugSafeHandle
    {
        private SafeAsn1StringHandle() :
            base(IntPtr.Zero, ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle()
        {
            Interop.Crypto.Asn1StringFree(handle);
            SetHandle(IntPtr.Zero);
            return true;
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }
    }

    internal sealed class SafeSharedAsn1StringHandle : SafeInteriorHandle
    {
        private SafeSharedAsn1StringHandle() :
            base(IntPtr.Zero, ownsHandle: true)
        {
        }
    }

    internal sealed class SafeSharedAsn1IntegerHandle : SafeInteriorHandle
    {
        private SafeSharedAsn1IntegerHandle() :
            base(IntPtr.Zero, ownsHandle: true)
        {
        }
    }
}
