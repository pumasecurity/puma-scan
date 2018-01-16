using System.Linq;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Common.Extensions;

namespace Puma.Security.Rules.Analyzer.Injection.Sql.Core
{
    internal class SqlCommandInjectionObjectCreationExpressionAnalyzer : ISqlCommandInjectionObjectCreationExpressionAnalyzer
    {
        public bool IsVulnerable(SemanticModel model, ObjectCreationExpressionSyntax syntax)
        {
            if (!ContainsSqlCommand(syntax))
                return false;

            var symbol = model.GetSymbolInfo(syntax).Symbol as IMethodSymbol;
            if (!IsSymbolSqlCommand(symbol))
                return false;

            if (syntax.ArgumentList != null && syntax.ArgumentList.Arguments.Any())
            {
                var commandTextArg = syntax.ArgumentList.Arguments[0].Expression;

                var expressionAnalyzer = SyntaxNodeAnalyzerFactory.Create(commandTextArg);
                if (expressionAnalyzer.CanIgnore(model, commandTextArg))
                    return false;
                if (expressionAnalyzer.CanSuppress(model, commandTextArg))
                    return false;
            }

            var commandTextInitializer =
                syntax.Initializer?.Expressions.OfType<AssignmentExpressionSyntax>()
                    .FirstOrDefault(p =>
                    {
                        var nameSyntax = p.Left as IdentifierNameSyntax;
                        return nameSyntax?.Identifier.ValueText == "CommandText";
                    });

            if (commandTextInitializer != null)
            {
                var expressionAnalyzer = SyntaxNodeAnalyzerFactory.Create(commandTextInitializer);
                if (expressionAnalyzer.CanIgnore(model, commandTextInitializer))
                    return false;
                if (expressionAnalyzer.CanSuppress(model, commandTextInitializer))
                    return false;
            }

            return commandTextInitializer != null || (syntax.ArgumentList != null && syntax.ArgumentList.Arguments.Any());
        }

        private bool IsSymbolSqlCommand(IMethodSymbol symbol)
        {
            return symbol.IsCtorFor("System.Data.SqlClient.SqlCommand");
        }


        private static bool ContainsSqlCommand(ObjectCreationExpressionSyntax syntax)
        {
            return syntax.ToString().Contains("SqlCommand");
        }
    }
}