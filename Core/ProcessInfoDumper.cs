using System;
using System.Collections.Generic;
using System.Diagnostics;
using LightJson;

namespace ProcessParentDumper.Core
{
    public class ProcessInfoDumper
    {
        private readonly IProcessInfoProvider _processInfoProvider;

        public ProcessInfoDumper(IProcessInfoProvider processInfoProvider)
        {
            _processInfoProvider = processInfoProvider ?? throw new ArgumentNullException(nameof(processInfoProvider));
        }

        public string DumpProcessInfo()
        {
            var output = new ProcessOutput
            {
                self = new Dictionary<string, int> { { "pid", Process.GetCurrentProcess().Id } },
                parents = new List<ProcessInfo>()
            };

            var currentProcess = Process.GetCurrentProcess();
            int? parentPid = _processInfoProvider.GetParentProcessId(currentProcess.Id);

            while (parentPid.HasValue && parentPid.Value != 0)
            {
                try
                {
                    var process = Process.GetProcessById(parentPid.Value);
                    var info = GetProcessInfo(process);
                    if (info != null)
                    {
                        output.parents.Add(info);
                    }
                    parentPid = _processInfoProvider.GetParentProcessId(parentPid.Value);
                }
                catch
                {
                    // Process may have exited or we may not have permission
                    break;
                }
            }

            // Convert to LightJson structure
            var jsonOutput = new JsonObject
            {
                ["self"] = new JsonObject { ["pid"] = output.self["pid"] },
                ["parents"] = new JsonArray()
            };

            // Convert each parent process info to JsonObject
            foreach (var parent in output.parents)
            {
                var parentJson = new JsonObject
                {
                    ["pid"] = parent.pid,
                    ["executable"] = parent.executable ?? "",
                    ["commandLine"] = parent.commandLine ?? ""
                };

                // Add environment variables
                if (parent.env != null)
                {
                    var envJson = new JsonObject();
                    foreach (var kvp in parent.env)
                    {
                        envJson[kvp.Key] = kvp.Value;
                    }
                    parentJson["env"] = envJson;
                }
                else
                {
                    parentJson["env"] = new JsonObject();
                }

                jsonOutput["parents"].AsJsonArray.Add(parentJson);
            }

            // Return the pretty-printed JSON string
            return jsonOutput.ToString(true);
        }

        private ProcessInfo GetProcessInfo(Process process)
        {
            var info = new ProcessInfo
            {
                pid = process.Id,
                executable = _processInfoProvider.GetProcessExecutablePath(process),
                commandLine = _processInfoProvider.GetProcessCommandLine(process),
                env = _processInfoProvider.GetProcessEnvironmentVariables(process)
            };

            return info;
        }
    }
}