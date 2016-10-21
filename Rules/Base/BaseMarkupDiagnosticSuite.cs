using System.Linq;

using Puma.Security.Rules.Analyzer;
using Puma.Security.Rules.Filters;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Puma.Security.Rules.Base
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class BaseMarkupDiagnosticSuite : BaseDiagnosticSuite
    {
        protected IFileExtensionFilter FileFilter;

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

            var srcFiles = FileFilter.GetFiles(context.Options.AdditionalFiles).ToList();

            if (!srcFiles.Any())
                return;

            foreach (IAdditionalTextAnalyzer analyzer in Analyzers)
            {
                var diagnosticInfo = analyzer.GetDiagnosticInfo(srcFiles, context.CancellationToken);
                foreach (var info in diagnosticInfo)
                {
                    var supportedDiagnostic = GetSupportedDiagnosticAttribute(analyzer);
                    var diagnostic = DiagnosticFactory.Create(supportedDiagnostic.GetDescriptor(), info);

                    context.ReportDiagnostic(diagnostic);
                }
            }
        }
    }
}