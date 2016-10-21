using System.Linq;

using Puma.Security.Rules.Analyzer;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Puma.Security.Rules.Base
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class BaseSyntaxDiagnosticSuite : BaseDiagnosticSuite
    {
        public override void Initialize(AnalysisContext context)
        {
            base.Initialize(context);

            var supportedKinds = Analyzers.Select(p => ((ISyntaxNodeAnalyzer) p).Kind).Distinct();
            foreach (var syntaxKind in supportedKinds)
            {
                context.RegisterSyntaxNodeAction(p => { AnalyzeNode(p, syntaxKind); }
                    , syntaxKind);
            }
        }

        private void AnalyzeNode(SyntaxNodeAnalysisContext context, SyntaxKind kind)
        {
            var analyzersForKind = Analyzers.Where(p => ((ISyntaxNodeAnalyzer) p).Kind == kind);
            foreach (ISyntaxNodeAnalyzer syntaxNodeAnalyzer in analyzersForKind)
            {
                var diagnosticInfo = syntaxNodeAnalyzer.GetDiagnosticInfo(context);
                foreach (var info in diagnosticInfo)
                {
                    var supportedDiagnostic = GetSupportedDiagnosticAttribute(syntaxNodeAnalyzer);
                    var diagnostic = DiagnosticFactory.Create(supportedDiagnostic.GetDescriptor(), info);

                    context.ReportDiagnostic(diagnostic);
                }
            }
        }
    }
}