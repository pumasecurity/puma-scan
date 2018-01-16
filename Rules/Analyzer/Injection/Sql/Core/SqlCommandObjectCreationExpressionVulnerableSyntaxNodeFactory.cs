using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Analyzer.Core;

namespace Puma.Security.Rules.Analyzer.Injection.Sql.Core
{
    internal class SqlCommandObjectCreationExpressionVulnerableSyntaxNodeFactory : ISqlCommandObjectCreationExpressionVulnerableSyntaxNodeFactory
    {
        public VulnerableSyntaxNode Create(ObjectCreationExpressionSyntax syntaxNode, params string[] messageArgs)
        {
            if (syntaxNode == null) throw new ArgumentNullException(nameof(syntaxNode));

            var sources = new List<SyntaxNode>();

            if (syntaxNode.ArgumentList != null && syntaxNode.ArgumentList.Arguments.Any())
            {
                var commandTextArg = syntaxNode.ArgumentList.Arguments[0].Expression;
                sources.Add(commandTextArg);
            }

            var commandTextInitializer =
                syntaxNode.Initializer?.Expressions.OfType<AssignmentExpressionSyntax>()
                    .FirstOrDefault(p =>
                    {
                        var nameSyntax = p.Left as IdentifierNameSyntax;
                        return nameSyntax?.Identifier.ValueText == "CommandText";
                    });

            if (commandTextInitializer != null)
            {
                sources.Add(commandTextInitializer);
            }

            return new VulnerableSyntaxNode(syntaxNode, sources.ToImmutableArray(), messageArgs);
        }
    }
}