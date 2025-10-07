namespace ProcessParentDumper.StdInOut
{
    public static class Stdio
    {
        public static IStdioOut Out = null;
        public static IStdioOut Err = null;
        public static IStdioIn In = null;
    }

    public interface IStdioOut
    {
        void Write(string text);
        void WriteLine(string line);
        void WriteLine();
    }

    public interface IStdioIn
    {
        string ReadLine();
    }
}
