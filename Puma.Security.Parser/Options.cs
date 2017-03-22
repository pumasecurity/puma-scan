using CommandLine;

namespace Puma.Security.Parser
{
    public class Options
    {
        [Option('w', "workspace", Required = true, HelpText = "Jenkins workspace root directory")]
        public string Workspace { get; set; }

        [Option('f', "file", Required = true, HelpText = "Build file to parse")]
        public string BuildFile { get; set; }

        [Option('o', "output", Required = true, HelpText = "Output file name")]
        public string OutputFile { get; set; }
    }
}