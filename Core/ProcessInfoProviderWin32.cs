using ProcessParentDumper.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace ProcessParentDumper
{
    public class ProcessInfoProviderWin32 : IProcessInfoProvider
    {
        public int? GetParentProcessId(int processId)
        {
            var objectAttributes = new NativeStructs.OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf(typeof(NativeStructs.OBJECT_ATTRIBUTES))
            };
            var clientId = new NativeStructs.CLIENT_ID { UniqueProcess = new IntPtr(processId) };

            var ntstatus = NativeMethods.NtOpenProcess(
                out IntPtr hProcess,
                Win32Enums.ACCESS_MASK.PROCESS_QUERY_INFORMATION,
                in objectAttributes,
                in clientId);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
                return null;

            try
            {
                var nInfoLength = (uint)Marshal.SizeOf(typeof(NativeStructs.PROCESS_BASIC_INFORMATION));
                IntPtr pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);

                ntstatus = NativeMethods.NtQueryInformationProcess(
                    hProcess,
                    Win32Enums.PROCESSINFOCLASS.ProcessBasicInformation,
                    pInfoBuffer,
                    nInfoLength,
                    out uint _);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Marshal.FreeHGlobal(pInfoBuffer);
                    return null;
                }

                var pbi = (NativeStructs.PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(NativeStructs.PROCESS_BASIC_INFORMATION));

                Marshal.FreeHGlobal(pInfoBuffer);

                return (int)pbi.InheritedFromUniqueProcessId.ToUInt32();
            }
            finally
            {
                NativeMethods.NtClose(hProcess);
            }
        }

        public string GetProcessExecutablePath(Process process)
        {
            try
            {
                // Try the .NET way first
                if (process.MainModule != null)
                    return process.MainModule.FileName;
                return null;
            }
            catch
            {
                // Fall back to native method
                return GetProcessExecutablePathNative(process.Id);
            }
        }

        private string GetProcessExecutablePathNative(int processId)
        {
            var objectAttributes = new NativeStructs.OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf(typeof(NativeStructs.OBJECT_ATTRIBUTES))
            };
            var clientId = new NativeStructs.CLIENT_ID { UniqueProcess = new IntPtr(processId) };

            var ntstatus = NativeMethods.NtOpenProcess(
                out IntPtr hProcess,
                Win32Enums.ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION,
                in objectAttributes,
                in clientId);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
                return null;

            try
            {
                var nInfoLength = (uint)(Marshal.SizeOf(typeof(NativeStructs.UNICODE_STRING)) + 512);
                var pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);

                ntstatus = NativeMethods.NtQueryInformationProcess(
                    hProcess,
                    Win32Enums.PROCESSINFOCLASS.ProcessImageFileName,
                    pInfoBuffer,
                    nInfoLength,
                    out uint _);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Marshal.FreeHGlobal(pInfoBuffer);
                    return null;
                }

                var info = (NativeStructs.UNICODE_STRING)Marshal.PtrToStructure(pInfoBuffer, typeof(NativeStructs.UNICODE_STRING));
                string imageFileName = info.ToString();

                Marshal.FreeHGlobal(pInfoBuffer);

                return imageFileName;
            }
            finally
            {
                NativeMethods.NtClose(hProcess);
            }
        }

        public string GetProcessCommandLine(Process process)
        {
            return GetProcessParameterString(process.Id, true);
        }

        public Dictionary<string, string> GetProcessEnvironmentVariables(Process process)
        {
            var env = new Dictionary<string, string>();
            bool enableDiagnostics = Environment.GetEnvironmentVariable("DUMPER_DEBUG") == "1";

            if (enableDiagnostics)
                Console.Error.WriteLine($"[ENV DEBUG] Attempting to get environment for PID {process.Id} ({process.ProcessName})");

            var objectAttributes = new NativeStructs.OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf(typeof(NativeStructs.OBJECT_ATTRIBUTES))
            };
            var clientId = new NativeStructs.CLIENT_ID { UniqueProcess = new IntPtr(process.Id) };

            var ntstatus = NativeMethods.NtOpenProcess(
                out IntPtr hProcess,
                Win32Enums.ACCESS_MASK.PROCESS_QUERY_INFORMATION | Win32Enums.ACCESS_MASK.PROCESS_VM_READ,
                in objectAttributes,
                in clientId);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                if (enableDiagnostics)
                {
                    Console.Error.WriteLine($"[ENV DEBUG] Failed to NtOpenProcess for PID {process.Id}. NTSTATUS: 0x{ntstatus:X}");
                }
                return env;
            }

            if (enableDiagnostics)
                Console.Error.WriteLine($"[ENV DEBUG] Successfully opened process handle: 0x{hProcess:X}");

            try
            {
                // Get PEB address
                if (!GetPebAddress(hProcess, out IntPtr pPeb, out IntPtr pPebWow32, enableDiagnostics))
                {
                    if (enableDiagnostics)
                        Console.Error.WriteLine($"[ENV DEBUG] Failed to get PEB address");
                    return env;
                }

                // Determine if this is a WOW64 process (32-bit on 64-bit OS)
                bool isWow64 = (pPebWow32 != IntPtr.Zero);
                IntPtr pPebToUse = isWow64 ? pPebWow32 : pPeb;

                if (enableDiagnostics)
                {
                    Console.Error.WriteLine($"[ENV DEBUG] PEB base address: 0x{pPeb:X}");
                    if (isWow64)
                        Console.Error.WriteLine($"[ENV DEBUG] Using WOW64 PEB: 0x{pPebWow32:X}");
                }

                // Get process parameters
                IntPtr pProcessParameters = GetProcessParameters(hProcess, pPebToUse, isWow64);

                if (pProcessParameters == IntPtr.Zero)
                {
                    if (enableDiagnostics)
                        Console.Error.WriteLine($"[ENV DEBUG] Failed to get process parameters");
                    return env;
                }

                IntPtr pEnvironment;
                ulong environmentSize;

                if (isWow64)
                {
                    // Read 32-bit structure
                    var processParams32 = (NativeStructs.RTL_USER_PROCESS_PARAMETERS32)Marshal.PtrToStructure(
                        pProcessParameters,
                        typeof(NativeStructs.RTL_USER_PROCESS_PARAMETERS32));

                    pEnvironment = new IntPtr(processParams32.Environment);

                    // For 32-bit processes, EnvironmentSize appears to be stored as uint (4 bytes) in actual memory
                    // even though the structure definition has it as ulong
                    int envSizeOffset = Marshal.OffsetOf(typeof(NativeStructs.RTL_USER_PROCESS_PARAMETERS32), "EnvironmentSize").ToInt32();
                    environmentSize = (ulong)Marshal.ReadInt32(pProcessParameters, envSizeOffset);

                    if (enableDiagnostics)
                    {
                        Console.Error.WriteLine($"[ENV DEBUG] Environment block address (32-bit): 0x{processParams32.Environment:X}, Size: {environmentSize}");
                    }
                }
                else
                {
                    // Read 64-bit structure
                    var processParams = (NativeStructs.RTL_USER_PROCESS_PARAMETERS)Marshal.PtrToStructure(
                        pProcessParameters,
                        typeof(NativeStructs.RTL_USER_PROCESS_PARAMETERS));

                    pEnvironment = processParams.Environment;
                    environmentSize = processParams.EnvironmentSize;

                    if (enableDiagnostics)
                        Console.Error.WriteLine($"[ENV DEBUG] Environment block address: 0x{processParams.Environment:X}, Size: {processParams.EnvironmentSize}");
                }

                Marshal.FreeHGlobal(pProcessParameters);

                if (pEnvironment == IntPtr.Zero || environmentSize == 0)
                {
                    if (enableDiagnostics)
                        Console.Error.WriteLine($"[ENV DEBUG] Environment block is null or size is 0");
                    return env;
                }

                // Convert environment size safely to uint
                uint nEnvironmentSize = (uint)Math.Min(environmentSize, uint.MaxValue);

                // Read and parse environment block
                env = EnumEnvironments(hProcess, pEnvironment, nEnvironmentSize);

                if (enableDiagnostics)
                    Console.Error.WriteLine($"[ENV DEBUG] Successfully read {env.Count} environment variables");
            }
            finally
            {
                NativeMethods.NtClose(hProcess);
            }

            return env;
        }

        private bool GetPebAddress(IntPtr hProcess, out IntPtr pPeb, out IntPtr pPebWow32, bool enableDiagnostics)
        {
            var nInfoLength = (uint)Marshal.SizeOf(typeof(NativeStructs.PROCESS_BASIC_INFORMATION));
            pPeb = IntPtr.Zero;
            pPebWow32 = IntPtr.Zero;

            if (enableDiagnostics)
            {
                Console.Error.WriteLine($"[ENV DEBUG] PROCESS_BASIC_INFORMATION struct size: {nInfoLength} bytes");
                Console.Error.WriteLine($"[ENV DEBUG] Environment.Is64BitProcess: {Environment.Is64BitProcess}");
                Console.Error.WriteLine($"[ENV DEBUG] IntPtr.Size: {IntPtr.Size}");
            }

            // Check for WOW64 (32-bit process on 64-bit OS)
            if (Environment.Is64BitProcess)
            {
                IntPtr pWow64Buffer = Marshal.AllocHGlobal(IntPtr.Size);
                var wow64Status = NativeMethods.NtQueryInformationProcess(
                    hProcess,
                    Win32Enums.PROCESSINFOCLASS.ProcessWow64Information,
                    pWow64Buffer,
                    (uint)IntPtr.Size,
                    out uint _);

                if (wow64Status == Win32Consts.STATUS_SUCCESS)
                {
                    pPebWow32 = Marshal.ReadIntPtr(pWow64Buffer);
                    if (enableDiagnostics)
                        Console.Error.WriteLine($"[ENV DEBUG] WOW64 PEB address: 0x{pPebWow32:X}");
                }

                Marshal.FreeHGlobal(pWow64Buffer);
            }

            IntPtr pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            var ntstatus = NativeMethods.NtQueryInformationProcess(
                hProcess,
                Win32Enums.PROCESSINFOCLASS.ProcessBasicInformation,
                pInfoBuffer,
                nInfoLength,
                out uint returnedLength);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                if (enableDiagnostics)
                    Console.Error.WriteLine($"[ENV DEBUG] NtQueryInformationProcess returned {returnedLength} bytes");

                var info = (NativeStructs.PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(NativeStructs.PROCESS_BASIC_INFORMATION));
                pPeb = info.PebBaseAddress;

                if (enableDiagnostics)
                {
                    Console.Error.WriteLine($"[ENV DEBUG] PROCESS_BASIC_INFORMATION:");
                    Console.Error.WriteLine($"[ENV DEBUG]   ExitStatus: 0x{info.ExitStatus:X}");
                    Console.Error.WriteLine($"[ENV DEBUG]   PebBaseAddress: 0x{info.PebBaseAddress:X}");
                    Console.Error.WriteLine($"[ENV DEBUG]   AffinityMask: 0x{info.AffinityMask:X}");
                    Console.Error.WriteLine($"[ENV DEBUG]   BasePriority: {info.BasePriority}");
                    Console.Error.WriteLine($"[ENV DEBUG]   UniqueProcessId: {info.UniqueProcessId}");
                    Console.Error.WriteLine($"[ENV DEBUG]   InheritedFromUniqueProcessId: {info.InheritedFromUniqueProcessId}");

                    // Dump raw bytes
                    Console.Error.Write($"[ENV DEBUG]   Raw bytes: ");
                    for (int i = 0; i < Math.Min(returnedLength, 48); i++)
                    {
                        Console.Error.Write($"{Marshal.ReadByte(pInfoBuffer, i):X2} ");
                    }
                    Console.Error.WriteLine();
                }
            }
            else if (enableDiagnostics)
            {
                Console.Error.WriteLine($"[ENV DEBUG] NtQueryInformationProcess failed. NTSTATUS: 0x{ntstatus:X}");
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }

        private IntPtr GetProcessParameters(IntPtr hProcess, IntPtr pPeb, bool bWow32)
        {
            int nOffset;
            uint nStructSize;
            uint nPointerSize;
            IntPtr pBufferToRead;
            IntPtr pProcessParameters = IntPtr.Zero;

            if (!Environment.Is64BitProcess || bWow32)
            {
                nOffset = Marshal.OffsetOf(typeof(NativeStructs.PEB32_PARTIAL), "ProcessParameters").ToInt32();
                nStructSize = (uint)Marshal.SizeOf(typeof(NativeStructs.RTL_USER_PROCESS_PARAMETERS32));
                nPointerSize = 4;
            }
            else
            {
                nOffset = Marshal.OffsetOf(typeof(NativeStructs.PEB64_PARTIAL), "ProcessParameters").ToInt32();
                nStructSize = (uint)Marshal.SizeOf(typeof(NativeStructs.RTL_USER_PROCESS_PARAMETERS));
                nPointerSize = 8;
            }

            if (Environment.Is64BitProcess)
                pBufferToRead = new IntPtr(pPeb.ToInt64() + nOffset);
            else
                pBufferToRead = new IntPtr(pPeb.ToInt32() + nOffset);

            IntPtr pInfoBuffer = ReadMemory(hProcess, pBufferToRead, nPointerSize, out uint _);

            if (pInfoBuffer == IntPtr.Zero)
                return IntPtr.Zero;

            IntPtr pProcessParametersBuffer;
            if (nPointerSize == 8)
                pProcessParametersBuffer = new IntPtr(Marshal.ReadInt64(pInfoBuffer));
            else
                pProcessParametersBuffer = new IntPtr(Marshal.ReadInt32(pInfoBuffer));

            Marshal.FreeHGlobal(pInfoBuffer);
            pProcessParameters = ReadMemory(hProcess, pProcessParametersBuffer, nStructSize, out uint _);

            return pProcessParameters;
        }

        private IntPtr ReadMemory(IntPtr hProcess, IntPtr pReadAddress, uint nSizeToRead, out uint nReturnedBytes)
        {
            IntPtr pBuffer = Marshal.AllocHGlobal((int)nSizeToRead);

            for (var idx = 0; idx < (int)nSizeToRead; idx++)
                Marshal.WriteByte(pBuffer, idx, 0);

            var ntstatus = NativeMethods.NtReadVirtualMemory(
                hProcess,
                pReadAddress,
                pBuffer,
                nSizeToRead,
                out nReturnedBytes);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Marshal.FreeHGlobal(pBuffer);
                pBuffer = IntPtr.Zero;
                nReturnedBytes = 0u;
            }

            return pBuffer;
        }

        private Dictionary<string, string> EnumEnvironments(IntPtr hProcess, IntPtr pEnvironment, uint nEnvironmentSize)
        {
            IntPtr pBufferToRead;
            int nOffset = 0;
            var environments = new Dictionary<string, string>();

            if ((pEnvironment == IntPtr.Zero) || (nEnvironmentSize == 0))
                return environments;

            pBufferToRead = ReadMemory(hProcess, pEnvironment, nEnvironmentSize, out uint _);

            if (pBufferToRead == IntPtr.Zero)
                return environments;

            while (nOffset < nEnvironmentSize)
            {
                if (Marshal.ReadInt32(pBufferToRead, nOffset) == 0)
                {
                    nOffset += 4;

                    while (Marshal.ReadInt16(pBufferToRead, nOffset) != 0)
                        nOffset += 2;
                }
                else if (Marshal.ReadInt16(pBufferToRead, nOffset) != 0)
                {
                    var keyBytes = new List<byte>();
                    var valueBytes = new List<byte>();

                    while (Marshal.ReadInt16(pBufferToRead, nOffset) != 0)
                    {
                        if (Marshal.ReadInt16(pBufferToRead, nOffset) == 0x3D)
                        {
                            nOffset += 2;
                            break;
                        }

                        for (int idx = 0; idx < 2; idx++)
                        {
                            keyBytes.Add(Marshal.ReadByte(pBufferToRead, nOffset));
                            nOffset++;
                        }
                    }

                    while (Marshal.ReadInt16(pBufferToRead, nOffset) != 0)
                    {
                        for (int idx = 0; idx < 2; idx++)
                        {
                            valueBytes.Add(Marshal.ReadByte(pBufferToRead, nOffset));
                            nOffset++;
                        }
                    }

                    if (valueBytes.Count > 0)
                    {
                        var key = Encoding.Unicode.GetString(keyBytes.ToArray());
                        var value = Encoding.Unicode.GetString(valueBytes.ToArray());

                        if (!environments.ContainsKey(key))
                            environments.Add(key, value);
                    }
                }
                else
                {
                    nOffset += 2;
                }
            }

            Marshal.FreeHGlobal(pBufferToRead);

            return environments;
        }

        private string GetProcessParameterString(int processId, bool isCommandLine)
        {
            var objectAttributes = new NativeStructs.OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf(typeof(NativeStructs.OBJECT_ATTRIBUTES))
            };
            var clientId = new NativeStructs.CLIENT_ID { UniqueProcess = new IntPtr(processId) };

            var ntstatus = NativeMethods.NtOpenProcess(
                out IntPtr hProcess,
                Win32Enums.ACCESS_MASK.PROCESS_QUERY_INFORMATION | Win32Enums.ACCESS_MASK.PROCESS_VM_READ,
                in objectAttributes,
                in clientId);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
                return null;

            try
            {
                // Get PEB address
                if (!GetPebAddress(hProcess, out IntPtr pPeb, out IntPtr pPebWow32, false))
                    return null;

                // Determine if this is a WOW64 process
                bool isWow64 = (pPebWow32 != IntPtr.Zero);
                IntPtr pPebToUse = isWow64 ? pPebWow32 : pPeb;

                // Get process parameters
                IntPtr pProcessParameters = GetProcessParameters(hProcess, pPebToUse, isWow64);

                if (pProcessParameters == IntPtr.Zero)
                    return null;

                IntPtr pStringBufferAddress;
                ushort stringLength;

                if (isWow64)
                {
                    // Read 32-bit structure
                    var processParams32 = (NativeStructs.RTL_USER_PROCESS_PARAMETERS32)Marshal.PtrToStructure(
                        pProcessParameters,
                        typeof(NativeStructs.RTL_USER_PROCESS_PARAMETERS32));

                    var unicodeString32 = isCommandLine ? processParams32.CommandLine : processParams32.ImagePathName;
                    pStringBufferAddress = new IntPtr(unicodeString32.Buffer);
                    stringLength = unicodeString32.Length;
                }
                else
                {
                    // Read 64-bit structure
                    var processParams = (NativeStructs.RTL_USER_PROCESS_PARAMETERS)Marshal.PtrToStructure(
                        pProcessParameters,
                        typeof(NativeStructs.RTL_USER_PROCESS_PARAMETERS));

                    var unicodeString = isCommandLine ? processParams.CommandLine : processParams.ImagePathName;
                    pStringBufferAddress = unicodeString.GetBuffer();
                    stringLength = unicodeString.Length;
                }

                Marshal.FreeHGlobal(pProcessParameters);

                if (pStringBufferAddress == IntPtr.Zero || stringLength == 0)
                    return null;

                // Read the actual string
                IntPtr pStringBuffer = ReadMemory(hProcess, pStringBufferAddress, stringLength, out uint _);

                if (pStringBuffer == IntPtr.Zero)
                    return null;

                string result = Marshal.PtrToStringUni(pStringBuffer);
                Marshal.FreeHGlobal(pStringBuffer);

                return result;
            }
            finally
            {
                NativeMethods.NtClose(hProcess);
            }
        }
    }
}
