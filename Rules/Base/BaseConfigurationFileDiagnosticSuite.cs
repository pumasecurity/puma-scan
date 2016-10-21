using System.Collections.Generic;
using System.Linq;

using Autofac;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

using Puma.Security.Rules.Analyzer;
using Puma.Security.Rules.Base.ConfigurationFiles;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Filters;
using Puma.Security.Rules.Model;

namespace Puma.Security.Rules.Base
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class BaseConfigurationFileDiagnosticSuite : BaseDiagnosticSuite
    {
        private readonly IFileExtensionFilter _fileFilter = new ConfigurationFileFilter();

        public override void Initialize(AnalysisContext context)
        {
            base.Initialize(context);
            //Run analysis on the compilation action
            context.RegisterCompilationAction(onCompilation);
        }

        private void onCompilation(CompilationAnalysisContext context)
        {
            if (!context.Options.AdditionalFiles.Any())
                return;

            var srcFiles = _fileFilter.GetFiles(context.Options.AdditionalFiles).ToList();

            if (!srcFiles.Any())
                return;

            //parse config files
            var configFiles = Parse(context, srcFiles).ToList();

            foreach (IConfigurationFileAnalyzer analyzer in Analyzers)
            {
                var diagnosticInfo = analyzer.GetDiagnosticInfo(configFiles, context.CancellationToken);
                foreach (var info in diagnosticInfo)
                {
                    var supportedDiagnostic = GetSupportedDiagnosticAttribute(analyzer);
                    var diagnostic = DiagnosticFactory.Create(supportedDiagnostic.GetDescriptor(), info);

                    context.ReportDiagnostic(diagnostic);
                }
            }
        }

        private IEnumerable<ConfigurationFile> Parse(CompilationAnalysisContext context,
            List<AdditionalText> srcFiles)
        {
            var parser = Container.Resolve<IConfigurationFileParser>();

            var workingDirectory = Utils.GetWorkingDirectory(context.Compilation.AssemblyName);
            var basePath = Utils.GetCommonRootPath(srcFiles);

            return srcFiles.Select(src => parser.Parse(src, basePath, workingDirectory)).ToList();
        }
    }
}