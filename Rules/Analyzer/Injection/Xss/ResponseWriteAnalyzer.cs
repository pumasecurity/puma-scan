using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Puma.Security.Rules.Model;
using Puma.Security.Rules.Diagnostics;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Analyzer.Injection.Xss.Core;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Puma.Security.Rules.Analyzer.Injection.Xss
{
    [SupportedDiagnostic(DiagnosticId.SEC0024)]
    public class ResponseWriteAnalyzer : ISyntaxNodeAnalyzer
    {
        private readonly IResponseWriteAssignmentExpressionAnalyzer _expressionSyntaxAnalyzer;

        public ResponseWriteAnalyzer(IResponseWriteAssignmentExpressionAnalyzer expressionSyntaxAnalyzer)
        {
            _expressionSyntaxAnalyzer = expressionSyntaxAnalyzer;
        }

        public SyntaxKind Kind => SyntaxKind.InvocationExpression;

        public IEnumerable<DiagnosticInfo> GetDiagnosticInfo(SyntaxNodeAnalysisContext context)
        {
            var result = new List<DiagnosticInfo>();
            var syntax = context.Node as InvocationExpressionSyntax;

            if (!_expressionSyntaxAnalyzer.IsVulnerable(context.SemanticModel, syntax))
                return result;

            result.Add(new DiagnosticInfo(syntax.GetLocation()));

            return result;
        }
    }
}
