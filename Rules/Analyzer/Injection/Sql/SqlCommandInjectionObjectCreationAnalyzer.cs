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
    internal class SqlCommandInjectionObjectCreationAnalyzer : BaseCodeBlockAnalyzer, ISyntaxAnalyzer
    {
        private readonly ISqlCommandInjectionObjectCreationExpressionAnalyzer _expressionSyntaxAnalyzer;
        private readonly ISqlCommandObjectCreationExpressionVulnerableSyntaxNodeFactory _vulnerableSyntaxNodeFactory;

        internal SqlCommandInjectionObjectCreationAnalyzer() : this(new SqlCommandInjectionObjectCreationExpressionAnalyzer(), new SqlCommandObjectCreationExpressionVulnerableSyntaxNodeFactory()) { }

        private SqlCommandInjectionObjectCreationAnalyzer(
            ISqlCommandInjectionObjectCreationExpressionAnalyzer expressionSyntaxAnalyzer,
            ISqlCommandObjectCreationExpressionVulnerableSyntaxNodeFactory vulnerableSyntaxNodeFactory)
        {
            _expressionSyntaxAnalyzer = expressionSyntaxAnalyzer;
            _vulnerableSyntaxNodeFactory = vulnerableSyntaxNodeFactory;
        }

        public SyntaxKind SinkKind => SyntaxKind.ObjectCreationExpression;

        public override void GetSinks(SyntaxNodeAnalysisContext context)
        {
            var syntax = context.Node as ObjectCreationExpressionSyntax;

            if (!_expressionSyntaxAnalyzer.IsVulnerable(context.SemanticModel, syntax))
                return;

            if (VulnerableSyntaxNodes.All(p => p.Sink.GetLocation() != syntax?.GetLocation()))
                VulnerableSyntaxNodes.Push(_vulnerableSyntaxNodeFactory.Create(syntax));
        }
    }
}