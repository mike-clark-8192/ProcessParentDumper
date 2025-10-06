using System.Collections.Generic;
using System.Diagnostics;

namespace ProcessParentDumper
{
    public interface IProcessInfoProvider
    {
        /// <summary>
        /// Gets the parent process ID for the specified process ID.
        /// </summary>
        /// <param name="processId">The process ID to get the parent for.</param>
        /// <returns>The parent process ID, or null if not found or accessible.</returns>
        int? GetParentProcessId(int processId);

        /// <summary>
        /// Gets the executable path for the specified process.
        /// </summary>
        /// <param name="process">The process to get the executable path for.</param>
        /// <returns>The executable path, or null if not accessible.</returns>
        string GetProcessExecutablePath(Process process);

        /// <summary>
        /// Gets the command line for the specified process.
        /// </summary>
        /// <param name="process">The process to get the command line for.</param>
        /// <returns>The command line string, or null if not accessible.</returns>
        string GetProcessCommandLine(Process process);

        /// <summary>
        /// Gets the environment variables for the specified process.
        /// </summary>
        /// <param name="process">The process to get environment variables for.</param>
        /// <returns>A dictionary of environment variables, or empty dictionary if not accessible.</returns>
        Dictionary<string, string> GetProcessEnvironmentVariables(Process process);
    }
}