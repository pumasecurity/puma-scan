using System.Linq;

using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Analyzer.Core.Factories;
using Puma.Security.Rules.Analyzer.Injection.Sql.Core;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Diagnostics;

namespace Puma.Security.Rules.Analyzer.Injection.Sql
{
    [SupportedDiagnostic(DiagnosticId.SEC0107)]
    internal class SqlCommandInjectionAssignmentAnalyzer : BaseCodeBlockAnalyzer, ISyntaxAnalyzer
    {
        private readonly ISqlCommandInjectionAssignmentExpressionAnalyzer _expressionSyntaxAnalyzer;
        private readonly IAssignmentExpressionVulnerableSyntaxNodeFactory _vulnerableSyntaxNodeFactory;

        internal SqlCommandInjectionAssignmentAnalyzer() : this(new SqlCommandInjectionAssignmentExpressionAnalyzer(), new AssignmentExpressionVulnerableSyntaxNodeFactory()) { }

        private SqlCommandInjectionAssignmentAnalyzer(
            ISqlCommandInjectionAssignmentExpressionAnalyzer expressionSyntaxAnalyzer,
            IAssignmentExpressionVulnerableSyntaxNodeFactory vulnerableSyntaxNodeFactory)
        {
            _expressionSyntaxAnalyzer = expressionSyntaxAnalyzer;
            _vulnerableSyntaxNodeFactory = vulnerableSyntaxNodeFactory;
        }

        public SyntaxKind SinkKind => SyntaxKind.SimpleAssignmentExpression;

        public override void GetSinks(SyntaxNodeAnalysisContext context)
        {
            var syntax = context.Node as AssignmentExpressionSyntax;

            if (!_expressionSyntaxAnalyzer.IsVulnerable(context.SemanticModel, syntax))
                return;

            if (VulnerableSyntaxNodes.All(p => p.Sink.GetLocation() != syntax?.GetLocation()))
                VulnerableSyntaxNodes.Push(_vulnerableSyntaxNodeFactory.Create(syntax));
        }
    }
}