using System.Collections.Generic;

namespace ProcessParentDumper.Core
{
    public class ProcessOutput
    {
        public Dictionary<string, int> self { get; set; }
        public List<ProcessInfo> parents { get; set; }
    }

    public class ProcessInfo
    {
        public int pid { get; set; }
        public string executable { get; set; }
        public string commandLine { get; set; }
        public Dictionary<string, string> env { get; set; }
    }
}