using System;

namespace ProcessParentDumper
{
    class Program
    {
        static void Main(string[] args)
        {
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
                Console.WriteLine(json);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error: " + ex.Message);
                Environment.Exit(1);
            }
        }
    }
}