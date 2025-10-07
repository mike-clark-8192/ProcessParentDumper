using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProcessParentDumper.StdInOut
{
    internal class DotnetStdio
    {
        public static void Install()
        {
            Stdio.Out = new DotnetStdout();
            Stdio.Err = new DotnetStderr();
            Stdio.In = null; // Program does not currently read from stdin
        }
    }

    internal class DotnetStdout : IStdioOut
    {
        public void Write(string text)
        {
            Console.Out.Write(text);
        }

        public void WriteLine(string line)
        {
            Console.Out.WriteLine(line);
        }

        public void WriteLine()
        {
            Console.Out.WriteLine();
        }
    }

    internal class DotnetStderr : IStdioOut
    {
        public void Write(string text)
        {
            Console.Error.Write(text);
        }

        public void WriteLine(string line)
        {
            Console.Error.WriteLine(line);
        }

        public void WriteLine()
        {
            Console.Error.WriteLine();
        }
    }

    internal class DotnetStdin : IStdioIn
    {
        public string ReadLine()
        {
            return Console.In.ReadLine();
        }
    }
}
