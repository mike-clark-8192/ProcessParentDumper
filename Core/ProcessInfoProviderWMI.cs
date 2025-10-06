using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;

namespace ProcessParentDumper
{
    public class ProcessInfoProviderWMI : IProcessInfoProvider
    {
        private class ProcessWMIInfo
        {
            public int? ParentProcessId { get; set; }
            public string ExecutablePath { get; set; }
            public string CommandLine { get; set; }
        }

        private ProcessWMIInfo GetProcessWMIInfo(int processId)
        {
            var info = new ProcessWMIInfo();

            try
            {
                // Query all properties at once for better performance and consistency
                using (var searcher = new ManagementObjectSearcher(
                    $"SELECT ParentProcessId, ExecutablePath, CommandLine FROM Win32_Process WHERE ProcessId = {processId}"))
                {
                    using (var results = searcher.Get())
                    {
                        foreach (ManagementObject mo in results)
                        {
                            var parentId = mo["ParentProcessId"];
                            if (parentId != null)
                            {
                                info.ParentProcessId = Convert.ToInt32(parentId);
                            }

                            var path = mo["ExecutablePath"];
                            if (path != null)
                            {
                                info.ExecutablePath = path.ToString();
                            }

                            var cmdLine = mo["CommandLine"];
                            if (cmdLine != null)
                            {
                                info.CommandLine = cmdLine.ToString();
                            }

                            // Only process first result (there should only be one)
                            break;
                        }
                    }
                }
            }
            catch
            {
                // Process may have exited or we may not have permission
            }

            return info;
        }

        public int? GetParentProcessId(int processId)
        {
            var info = GetProcessWMIInfo(processId);
            return info.ParentProcessId;
        }

        public string GetProcessExecutablePath(Process process)
        {
            var info = GetProcessWMIInfo(process.Id);
            return info.ExecutablePath;
        }

        public string GetProcessCommandLine(Process process)
        {
            var info = GetProcessWMIInfo(process.Id);

            // If WMI doesn't return command line, try alternative method
            if (string.IsNullOrEmpty(info.CommandLine))
            {
                try
                {
                    // Try using GetCommandLine method if available
                    using (var searcher = new ManagementObjectSearcher(
                        $"SELECT * FROM Win32_Process WHERE ProcessId = {process.Id}"))
                    {
                        using (var results = searcher.Get())
                        {
                            foreach (ManagementObject mo in results)
                            {
                                // Check if CommandLine property exists with a value
                                foreach (PropertyData prop in mo.Properties)
                                {
                                    if (prop.Name == "CommandLine" && prop.Value != null)
                                    {
                                        info.CommandLine = prop.Value.ToString();
                                        break;
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
                catch
                {
                    // Alternative method failed, command line remains null
                }
            }

            return info.CommandLine;
        }

        public Dictionary<string, string> GetProcessEnvironmentVariables(Process process)
        {
            // WMI doesn't provide direct access to environment variables
            // You could use Win32_ProcessStartup but it only works for processes you start yourself
            // For existing processes, we would need to fall back to Win32 API methods
            // For now, returning an empty dictionary to keep the WMI implementation pure
            return new Dictionary<string, string>();

            // Alternative: You could call into ProcessInfoProviderWin32's method here if you want
            // var win32Provider = new ProcessInfoProviderWin32();
            // return win32Provider.GetProcessEnvironmentVariables(process);
        }
    }
}