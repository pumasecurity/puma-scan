using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Analyzer.Core;

namespace Puma.Security.Rules.Analyzer.Injection.Sql.Core
{
    internal class SqlCommandInjectionAssignmentExpressionAnalyzer : ISqlCommandInjectionAssignmentExpressionAnalyzer
    {
        public bool IsVulnerable(SemanticModel model, AssignmentExpressionSyntax syntax)
        {
            var leftSyntax = syntax?.Left as MemberAccessExpressionSyntax;

            if (leftSyntax == null || leftSyntax.Name.Identifier.ValueText.ToLower() != "commandtext") return false;

            var leftSymbol = model.GetSymbolInfo(leftSyntax).Symbol;

            if (!(leftSymbol != null && leftSymbol.ToString().StartsWith("System.Data.SqlClient.SqlCommand"))) return false;

            var expressionAnalyzer = SyntaxNodeAnalyzerFactory.Create(syntax.Right);
            if (expressionAnalyzer.CanIgnore(model, syntax.Right))
                return false;
            if (expressionAnalyzer.CanSuppress(model, syntax.Right))
                return false;

            return true;
        }
    }
}