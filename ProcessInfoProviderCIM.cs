using System;
using System.Collections.Generic;
using System.Management.Infrastructure;
using System.Diagnostics;

namespace ProcessParentDumper
{
    public class ProcessInfoProviderCIM : IProcessInfoProvider
    {
        private const string Namespace = @"root\cimv2";
        private const string QueryLanguage = "WQL";
        private const string ClassName = "Win32_Process";

        public int? GetParentProcessId(int processId)
        {
            try
            {
                using (var cimSession = CimSession.Create(null))
                {
                    var query = $"SELECT ParentProcessId FROM {ClassName} WHERE ProcessId = {processId}";
                    var result = cimSession.QueryInstances(Namespace, QueryLanguage, query).FirstOrDefault();

                    if (result != null && result.CimInstanceProperties["ParentProcessId"].Value is uint parentId)
                    {
                        // Some system processes might have a ParentProcessId of 0.
                        if (parentId == 0)
                        {
                            return null;
                        }
                        return (int)parentId;
                    }
                }
            }
            catch (Exception ex)
            {
                // Log the exception, e.g., using a logging framework
                Console.WriteLine($"Error getting parent process ID: {ex.Message}");
            }

            return null;
        }

        public string GetProcessExecutablePath(Process process)
        {
            try
            {
                using (var cimSession = CimSession.Create(null))
                {
                    var query = $"SELECT ExecutablePath FROM {ClassName} WHERE ProcessId = {process.Id}";
                    var result = cimSession.QueryInstances(Namespace, QueryLanguage, query).FirstOrDefault();

                    if (result != null && result.CimInstanceProperties["ExecutablePath"].Value is string path)
                    {
                        return path;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting executable path: {ex.Message}");
            }
            return null;
        }

        public string GetProcessCommandLine(Process process)
        {
            try
            {
                using (var cimSession = CimSession.Create(null))
                {
                    var query = $"SELECT CommandLine FROM {ClassName} WHERE ProcessId = {process.Id}";
                    var result = cimSession.QueryInstances(Namespace, QueryLanguage, query).FirstOrDefault();

                    if (result != null && result.CimInstanceProperties["CommandLine"].Value is string commandLine)
                    {
                        return commandLine;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting command line: {ex.Message}");
            }
            return null;
        }

        public Dictionary<string, string> GetProcessEnvironmentVariables(Process process)
        {
            // CIM does not expose this information for other processes.
            // A possible alternative would be to read the PEB (Process Environment Block)
            // using Windows API calls and ReadProcessMemory, but this is a
            // significantly more complex and elevated-privilege operation.
            return new Dictionary<string, string>();
        }
    }
}
