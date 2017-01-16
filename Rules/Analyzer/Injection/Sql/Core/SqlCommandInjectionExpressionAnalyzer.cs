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

namespace Puma.Security.Rules.Analyzer.Injection.Sql.Core
{
    public class SqlCommandInjectionExpressionAnalyzer : ISqlCommandInjectionExpressionAnalyzer
    {
        public bool IsVulnerable(SemanticModel model, InvocationExpressionSyntax syntax)
        {
            if (ContainsSqlCommands(syntax))
            {
                var symbol = model.GetSymbolInfo(syntax).Symbol as IMethodSymbol;
                if (IsSymbolSqlCommand(symbol))
                {
                    var memberAccess = syntax.Expression as MemberAccessExpressionSyntax;
                    var identifier = memberAccess?.Expression as IdentifierNameSyntax;

                    var containingBlock = syntax.FirstAncestorOrSelf<BlockSyntax>();
                    if (containingBlock == null) return false;


                    var commandText = GetCommandTextFromConstructor(containingBlock, identifier) ??
                                      GetCommandTextFromAssignment(containingBlock, identifier);
                    if (commandText != null)
                    {
                        return !(commandText is LiteralExpressionSyntax);
                    }

                    return true;
                }
            }
            return false;
        }

        private bool IsSymbolSqlCommand(IMethodSymbol symbol)
        => symbol.IsMethod("System.Data.SqlClient.SqlCommand", "ExecuteReader") ||
           symbol.IsMethod("System.Data.SqlClient.SqlCommand", "ExecuteNonQuery") ||
           symbol.IsMethod("System.Data.SqlClient.SqlCommand", "ExecuteScalar");


        private static bool ContainsSqlCommands(InvocationExpressionSyntax syntax)
            => syntax.ToString().Contains("ExecuteReader") ||
               syntax.ToString().Contains("ExecuteNonQuery") ||
               syntax.ToString().Contains("ExecuteScalar");

        private static SyntaxNode GetCommandTextFromAssignment(BlockSyntax containingBlock,
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
                        return leftExpression?.Name.Identifier.ValueText == "CommandText";
                    }

                    return false;
                }).ToList();

            if (assignments.Any() && assignments.Count == 1)
            {
                return assignments.First().Right;
            }
            return null;
        }

        private static SyntaxNode GetCommandTextFromConstructor(BlockSyntax containingBlock,
            IdentifierNameSyntax identifier)
        {
            var objectCreations = containingBlock.DescendantNodes()
                .OfType<ObjectCreationExpressionSyntax>()
                .Where(p =>
                {
                    var type = p.Type as IdentifierNameSyntax;
                    if (type?.Identifier.ValueText == "SqlCommand")
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
                var sqlCommandCreation = objectCreations.First();
                if (sqlCommandCreation.ArgumentList != null && sqlCommandCreation.ArgumentList.Arguments.Any())
                {
                    return sqlCommandCreation.ArgumentList.Arguments[0].Expression;
                }

                //look in object initializer
                var commandText =
                    sqlCommandCreation.Initializer?.Expressions.OfType<AssignmentExpressionSyntax>()
                        .FirstOrDefault(p =>
                        {
                            var nameSyntax = p.Left as IdentifierNameSyntax;
                            return nameSyntax?.Identifier.ValueText == "CommandText";
                        });

                if (commandText != null)
                {
                    return commandText.Right;
                }
            }

            return null;
        }
    }
}