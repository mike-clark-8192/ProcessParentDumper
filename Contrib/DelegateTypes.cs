using System;
using System.Runtime.InteropServices;
using ProcessParentDumper.Win32Enums;

namespace ProcessParentDumper.Win32
{
    internal static class DelegateTypes
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool DllMain(IntPtr hinstDLL, DLLMAIN_CALL_REASON fdwReason, IntPtr lpvReserved);
    
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate void IMAGE_TLS_CALLBACK(IntPtr DllHandle, DLLMAIN_CALL_REASON Reason, IntPtr Reserved);
    }

}