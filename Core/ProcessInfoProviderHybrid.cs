using System.Collections.Generic;
using System.Diagnostics;

namespace ProcessParentDumper
{
    /// <summary>
    /// Hybrid provider that uses WMI for most operations but falls back to Win32 API for command lines when needed
    /// </summary>
    public class ProcessInfoProviderHybrid : IProcessInfoProvider
    {
        private readonly ProcessInfoProviderWMI _wmiProvider;
        private readonly ProcessInfoProviderWin32 _win32Provider;

        public ProcessInfoProviderHybrid()
        {
            _wmiProvider = new ProcessInfoProviderWMI();
            _win32Provider = new ProcessInfoProviderWin32();
        }

        public int? GetParentProcessId(int processId)
        {
            // WMI is generally reliable for parent process IDs
            return _wmiProvider.GetParentProcessId(processId);
        }

        public string GetProcessExecutablePath(Process process)
        {
            // Try WMI first
            var path = _wmiProvider.GetProcessExecutablePath(process);

            // If WMI fails, fall back to Win32
            if (string.IsNullOrEmpty(path))
            {
                path = _win32Provider.GetProcessExecutablePath(process);
            }

            return path;
        }

        public string GetProcessCommandLine(Process process)
        {
            // Try WMI first (often more successful for command lines)
            var cmdLine = _wmiProvider.GetProcessCommandLine(process);

            // If WMI returns null or empty, try Win32 API
            if (string.IsNullOrEmpty(cmdLine))
            {
                cmdLine = _win32Provider.GetProcessCommandLine(process);
            }

            return cmdLine;
        }

        public Dictionary<string, string> GetProcessEnvironmentVariables(Process process)
        {
            // Only Win32 API can get environment variables
            return _win32Provider.GetProcessEnvironmentVariables(process);
        }
    }
}