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
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Puma.Security.Rules.Analyzer.Core
{
    internal static class SyntaxNodeAnalyzerFactory
    {
        internal static ISyntaxNodeAnalyzer Create(SyntaxNode syntax)
        {
            switch (syntax)
            {
                case ArgumentListSyntax _:
                    return new ArgumentListSyntaxAnalyzer();
                case ArgumentSyntax _:
                    return new ArgumentSyntaxNodeAnalyzer();
                case BinaryExpressionSyntax _:
                    return new BinaryExpressionSyntaxAnalyzer();
                case ConditionalExpressionSyntax _:
                    return new ConditionalExpressionSyntaxAnalyzer();
                case ElementAccessExpressionSyntax _:
                    return new ElementAccessExpressionSyntaxAnalyzer();
                case IdentifierNameSyntax _:
                    return new IdentifierNameSyntaxAnalyzer();
                case InvocationExpressionSyntax _:
                    return new InvocationExpressionSyntaxAnalyzer();
                case LiteralExpressionSyntax _:
                    return new LiteralExpressionSyntaxAnalyzer();
                case MemberAccessExpressionSyntax _:
                    return new MemberAccessExpressionSyntaxAnalyzer();
                case ParameterSyntax _:
                    return new ParameterSyntaxNodeAnalyzer();
                case QueryExpressionSyntax _:
                    return new QueryExpressionSyntaxAnalyzer();
            }

            return new BaseSyntaxNodeAnalyzer<SyntaxNode>();
        }
    }
}