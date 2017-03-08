/* 
 * Copyright(c) 2016 - 2017 Puma Security, LLC (https://www.pumascan.com)
 * 
 * Project Leader: Eric Johnson (eric.johnson@pumascan.com)
 * Lead Developer: Eric Mead (eric.mead@pumascan.com)
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

using System.Linq;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Common.Extensions;

namespace Puma.Security.Rules.Analyzer.Injection.Ldap.Core
{
    public class LdapDirectorySearcherInjectionExpressionAnalyzer : ILdapDirectorySearcherInjectionExpressionAnalyzer
    {
        public bool IsVulnerable(SemanticModel model, InvocationExpressionSyntax syntax)
        {
            if (ContainsSearchCommands(syntax))
            {
                var symbol = model.GetSymbolInfo(syntax).Symbol as IMethodSymbol;
                if (IsSearchCommand(symbol))
                {
                    var memberAccess = syntax.Expression as MemberAccessExpressionSyntax;
                    var identifier = memberAccess?.Expression as IdentifierNameSyntax;

                    var containingBlock = syntax.FirstAncestorOrSelf<BlockSyntax>();
                    if (containingBlock == null) return false;

                    var filter = GetFilterFromConstructor(model, containingBlock, identifier) ??
                                      GetFilterFromAssignment(containingBlock, identifier);
                    
                    if (filter != null)
                    {
                        return !(filter is LiteralExpressionSyntax);
                    }

                    return true;
                }
            }
            return false;
        }

        private bool IsSearchCommand(IMethodSymbol symbol)
        => symbol.IsMethod("System.DirectoryServices.DirectorySearcher", "FindOne") ||
           symbol.IsMethod("System.DirectoryServices.DirectorySearcher", "FindAll");

        private static bool ContainsSearchCommands(InvocationExpressionSyntax syntax)
            => syntax.ToString().Contains("FindOne") ||
               syntax.ToString().Contains("FindAll");

        private static SyntaxNode GetFilterFromAssignment(BlockSyntax containingBlock,
                IdentifierNameSyntax identifier)
        {
            var assignments = containingBlock.DescendantNodes()
                .OfType<AssignmentExpressionSyntax>()
                .Where(p =>
                {
                    var leftExpression = p.Left as MemberAccessExpressionSyntax;
                    var leftIdentifier = leftExpression?.Expression as IdentifierNameSyntax;

                    if (leftIdentifier?.Identifier.ValueText == identifier.Identifier.ValueText)
                    {
                        return leftExpression?.Name.Identifier.ValueText == "Filter";
                    }

                    return false;
                }).ToList();

            if (assignments.Any() && assignments.Count == 1)
            {
                return assignments.First().Right;
            }
            return null;
        }

        private static SyntaxNode GetFilterFromConstructor(SemanticModel model, BlockSyntax containingBlock,
            IdentifierNameSyntax identifier)
        {
            var objectCreations = containingBlock.DescendantNodes()
                .OfType<ObjectCreationExpressionSyntax>()
                .Where(p =>
                {
                    var type = p.Type as IdentifierNameSyntax;
                    if (type?.Identifier.ValueText == "DirectorySearcher")
                    {
                        var declaration = p.Parent?.Parent as VariableDeclaratorSyntax;
                        return declaration.Identifier.ValueText == identifier.Identifier.ValueText;
                    }

                    return false;
                }).ToList();

            //make sure there is one and only one, otherwise we'd be guessing on the correct one. 
            //I.e. they are in the middle of refactoring code and copy/pasted the object.
            if (objectCreations.Any() && objectCreations.Count() == 1)
            {
                //look in args
                var directorySearcherCreation = objectCreations.First();
                if (directorySearcherCreation.ArgumentList != null &&
                    directorySearcherCreation.ArgumentList.Arguments.Any())
                {
                    var firstArg = directorySearcherCreation.ArgumentList.Arguments[0].Expression;
                    //if first param is string literal, it's the filter
                    if (firstArg is LiteralExpressionSyntax)
                    {
                        return directorySearcherCreation.ArgumentList.Arguments[0].Expression;
                    }

                    //if first param is of type DirectoryEntry, then second param (if present) is filters
                    var localSymbol = model.GetSymbolInfo(firstArg).Symbol as ILocalSymbol;
                    if (localSymbol?.Type.Name == "DirectoryEntry")
                    {
                        if (directorySearcherCreation.ArgumentList.Arguments.Count > 1)
                        {
                            return directorySearcherCreation.ArgumentList.Arguments[1].Expression;
                        }
                    }

                    //if first param is of type DirectoryEntry, then second param (if present) is filters
                    var methodSymbol = model.GetSymbolInfo(firstArg).Symbol as IMethodSymbol;
                    if (methodSymbol.IsCtorFor("System.DirectoryServices.DirectoryEntry"))
                    {
                        if (directorySearcherCreation.ArgumentList.Arguments.Count > 1)
                        {
                            return directorySearcherCreation.ArgumentList.Arguments[1].Expression;
                        }
                    }

                    //if first param is of type DirectoryEntry, then second param (if present) is filters
                    var parameterSymbol = model.GetSymbolInfo(firstArg).Symbol as IParameterSymbol;
                    if (parameterSymbol?.Type.ToString() == "System.DirectoryServices.DirectoryEntry")
                    {
                        if (directorySearcherCreation.ArgumentList.Arguments.Count > 1)
                        {
                            return directorySearcherCreation.ArgumentList.Arguments[1].Expression;
                        }
                    }

                    //look in object initializer
                    var filter =
                        directorySearcherCreation.Initializer?.Expressions.OfType<AssignmentExpressionSyntax>()
                            .FirstOrDefault(p =>
                            {
                                var nameSyntax = p.Left as IdentifierNameSyntax;
                                return nameSyntax?.Identifier.ValueText == "Filter";
                            });

                    if (filter != null)
                    {
                        return filter.Right;
                    }
                }
            }

            return null;
        }
    }
}