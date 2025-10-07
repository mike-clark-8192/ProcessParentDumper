using System;
using ProcessParentDumper.Core;
using ProcessParentDumper.StdInOut;

namespace ProcessParentDumper
{
    class Program
    {
        /*
         * jq hint:
         * 
         * ProcessParentDumper.exe | jq 'del(.parents[].env)' 
         * 
         */
        static void Main(string[] args)
        {
            DotnetRedoStdio.Install();

            try
            {
                // Determine which provider to use
                IProcessInfoProvider provider;
                string providerType = args.Length > 0 ? args[0].ToLower() : "win32";

                switch (providerType)
                {
                    case "wmi":
                        provider = new ProcessInfoProviderWMI();
                        break;
                    case "win32":
                        provider = new ProcessInfoProviderWin32();
                        break;
                    case "hybrid":
                    default:
                        // Default to hybrid for best results
                        provider = new ProcessInfoProviderHybrid();
                        break;
                }

                // Create the dumper with the provider
                ProcessInfoDumper dumper = new ProcessInfoDumper(provider);

                // Dump the process info
                string json = dumper.DumpProcessInfo();
                Stdio.Out.WriteLine(json);
            }
            catch (Exception ex)
            {
                Stdio.Err.WriteLine("Error: " + ex.Message);
                Environment.Exit(1);
            }
        }
    }
}
