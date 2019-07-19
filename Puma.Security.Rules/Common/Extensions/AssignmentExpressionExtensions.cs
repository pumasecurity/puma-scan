/* 
 * Copyright(c) 2016 - 2019 Puma Security, LLC (https://www.pumascan.com)
 * 
 * Project Leader: Eric Johnson (eric.johnson@pumascan.com)
 * Lead Developer: Eric Mead (eric.mead@pumascan.com)
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Linq;

namespace Puma.Security.Rules.Common.Extensions
{
    internal static class AssignmentExpressionExtensions
    {
        internal static bool IsFalse(this AssignmentExpressionSyntax syntax, SemanticModel model)
        {
            var result = IsFalseLiteralExpression(syntax);

            if (!result)
                result = IsFalseLamdaExpression(syntax);

            if (!result)
                result = IsFalseMethod(syntax, model);

            if (!result)
                result = IsFalseDelegateMethod(syntax);

            return result;
        }

        internal static bool IsFalseLiteralExpression(this AssignmentExpressionSyntax syntax)
        {
            return syntax?.Right is LiteralExpressionSyntax && syntax?.Right?.Kind() == SyntaxKind.FalseLiteralExpression;
        }

        internal static bool IsFalseMethod(this AssignmentExpressionSyntax syntax, SemanticModel model)
        {
            var identifierNameSyntax = syntax.Right as IdentifierNameSyntax;
            if (identifierNameSyntax != null)
            {
                var method = model.SyntaxTree.GetRoot().DescendantNodes().OfType<MethodDeclarationSyntax>()
                    .Where(p => p.Identifier.ValueText == identifierNameSyntax.Identifier.ValueText);

                var methodReturnsHardcodedTrue =
                    method.Any(p => p.DescendantNodes().OfType<ReturnStatementSyntax>().Any(
                        q =>
                            q.Expression is LiteralExpressionSyntax &&
                            q.Expression.Kind() == SyntaxKind.FalseLiteralExpression));

                if (methodReturnsHardcodedTrue)
                    return true;
            }
            return false;
        }

        internal static bool IsFalseDelegateMethod(this AssignmentExpressionSyntax syntax)
        {
            var anonymousMethodExpressionSyntax = syntax.Right as AnonymousMethodExpressionSyntax;
            var anonymousBlock = anonymousMethodExpressionSyntax?.Body as BlockSyntax;
            if (anonymousBlock == null) return false;

            return anonymousBlock.DescendantNodes()
                .OfType<ReturnStatementSyntax>()
                .Any(
                    p =>
                        p.Expression is LiteralExpressionSyntax &&
                        p.Expression.Kind() == SyntaxKind.FalseLiteralExpression);
        }

        internal static bool IsFalseLamdaExpression(this AssignmentExpressionSyntax syntax)
        {
            var lambdaExpressionSyntax = syntax.Right as ParenthesizedLambdaExpressionSyntax;

            return lambdaExpressionSyntax?.Body is LiteralExpressionSyntax &&
                   lambdaExpressionSyntax.Body.Kind() == SyntaxKind.FalseLiteralExpression;
        }

        internal static bool IsNullLiteralExpression(this AssignmentExpressionSyntax syntax)
        {
            return syntax?.Right is LiteralExpressionSyntax && syntax?.Right?.Kind() == SyntaxKind.NullLiteralExpression;
        }
    }
}
