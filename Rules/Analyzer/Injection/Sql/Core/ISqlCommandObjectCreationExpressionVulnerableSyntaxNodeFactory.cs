using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Analyzer.Core.Factories;

namespace Puma.Security.Rules.Analyzer.Injection.Sql.Core
{
    internal interface ISqlCommandObjectCreationExpressionVulnerableSyntaxNodeFactory : IVulnerableSyntaxNodeFactory<ObjectCreationExpressionSyntax>
    {

    }
}