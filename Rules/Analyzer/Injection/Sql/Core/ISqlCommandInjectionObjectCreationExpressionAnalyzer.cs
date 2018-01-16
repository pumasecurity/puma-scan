using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Puma.Security.Rules.Analyzer.Injection.Sql.Core
{
    internal interface ISqlCommandInjectionObjectCreationExpressionAnalyzer
    {
        bool IsVulnerable(SemanticModel model, ObjectCreationExpressionSyntax syntax);
    }
}