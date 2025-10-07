using System;
using System.IO;

namespace ProcessParentDumper.StdInOut
{
    internal class DotnetRedoStdio
    {
        public static void Install()
        {
            var stdoutWriter = CreateWriter(Console.OpenStandardOutput);
            Console.SetOut(stdoutWriter);

            var stderrWriter = CreateWriter(Console.OpenStandardError);
            Console.SetError(stderrWriter);

            Stdio.Out = new DotnetStdout();
            Stdio.Err = new DotnetStderr();
            Stdio.In = null;
        }

        private static StreamWriter CreateWriter(Func<Stream> streamFactory)
        {
            Stream stream;
            try
            {
                stream = streamFactory();
            }
            catch (IOException)
            {
                stream = Stream.Null;
            }
            catch (UnauthorizedAccessException)
            {
                stream = Stream.Null;
            }

            var writer = new StreamWriter(stream)
            {
                AutoFlush = true
            };
            return writer;
        }
    }
}
