using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Puma.Security.Rules.Analyzer.Injection.Sql.Core
{
    public interface ILinqSqlInjectionExpressionAnalyzer
    {
        bool IsVulnerable(SemanticModel model, InvocationExpressionSyntax syntax);
    }
}