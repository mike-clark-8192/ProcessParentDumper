using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.Json;

namespace ProcessParentDumper
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

            var options = new JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            };
            return JsonSerializer.Serialize(output, options);
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