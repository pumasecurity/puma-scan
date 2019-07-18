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

using System.Linq;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Common;

namespace Puma.Security.Rules.Analyzer.Validation.Certificate.Core
{
    internal class HttpWebRequestCertificateValidationExpressionAnalyzer :
        IHttpWebRequestCertificateValidationExpressionAnalyzer
    {
        public bool IsVulnerable(SemanticModel model, AssignmentExpressionSyntax syntax, DiagnosticId ruleId)
        {
            if (!ContainsCertificateValidationCallback(syntax))
                return false;

            var symbol = ModelExtensions.GetSymbolInfo(model, syntax.Left).Symbol as IPropertySymbol;
            if (symbol == null)
                return false;

            //TODO: only flagging those hard-coding a return value of true. Therefore could miss scenarios where the value is hardcoded in a const, config value. 
            if (symbol.Name == "ServerCertificateValidationCallback" &&
                symbol.ContainingType.Name == "HttpWebRequest")
            {
                if (IsTrueLamdaExpression(syntax))
                    return true;

                if (IsTrueDelegateMethod(syntax))
                    return true;

                if (IsTrueMethod(model, syntax))
                    return true;
            }

            return false;
        }

        private static bool IsTrueMethod(SemanticModel model, AssignmentExpressionSyntax syntax)
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
                            q.Expression.Kind() == SyntaxKind.TrueLiteralExpression));

                if (methodReturnsHardcodedTrue)
                    return true;
            }
            return false;
        }

        private static bool IsTrueDelegateMethod(AssignmentExpressionSyntax syntax)
        {
            var anonymousMethodExpressionSyntax = syntax.Right as AnonymousMethodExpressionSyntax;
            var anonymousBlock = anonymousMethodExpressionSyntax?.Body as BlockSyntax;
            if (anonymousBlock == null) return false;

            return anonymousBlock.DescendantNodes()
                .OfType<ReturnStatementSyntax>()
                .Any(
                    p =>
                        p.Expression is LiteralExpressionSyntax &&
                        p.Expression.Kind() == SyntaxKind.TrueLiteralExpression);
        }

        private static bool IsTrueLamdaExpression(AssignmentExpressionSyntax syntax)
        {
            var lambdaExpressionSyntax = syntax.Right as ParenthesizedLambdaExpressionSyntax;

            return lambdaExpressionSyntax?.Body is LiteralExpressionSyntax &&
                   lambdaExpressionSyntax.Body.Kind() == SyntaxKind.TrueLiteralExpression;
        }

        private static bool ContainsCertificateValidationCallback(AssignmentExpressionSyntax syntax)
        {
            return syntax.ToString().Contains("ServerCertificateValidationCallback");
        }
    }
}