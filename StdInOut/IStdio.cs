namespace ProcessParentDumper.Stdio
{
    internal class Stdio
    {
        internal static IStdo Out = null;
        internal static IStdo Err = null;
        internal static IStdi In = null;
    }

    internal interface IStdo
    {
        void Write(string text);
        void WriteLine(string line);
    }

    internal interface IStdi
    {
        string ReadLine();
    }
}
