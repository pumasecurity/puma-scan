using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;

namespace Puma.Security.Rules.Analyzer.AccessControl.Authorize.Core
{
    interface IAuthorizeExpressionAnalyzer
    {
        List<SyntaxNode> IsVulnerable(SemanticModel model, ClassDeclarationSyntax syntax);
    }
}
