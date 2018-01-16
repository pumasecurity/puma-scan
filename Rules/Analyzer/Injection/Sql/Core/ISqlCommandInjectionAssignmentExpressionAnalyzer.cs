using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Puma.Security.Rules.Analyzer.Injection.Sql.Core
{
    internal interface ISqlCommandInjectionAssignmentExpressionAnalyzer
    {
        bool IsVulnerable(SemanticModel model, AssignmentExpressionSyntax syntax);
    }
}