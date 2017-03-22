namespace Puma.Security.Parser
{
    public class Instance
    {
        public string Category { get; set; }

        public string Path { get; set; }

        public int ColumnNumber{ get; set; }

        public int LineNumber { get; set; }

        public string Message { get; set; }

        public string Project { get; set; }
    }
}