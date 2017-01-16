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

using Puma.Security.Rules.Diagnostics;
using Puma.Security.Rules.Model;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using System;
using System.Collections.Generic;
using Puma.Security.Rules.Common;

namespace Puma.Security.Rules.Analyzer.Configuration.Identity
{
    [SupportedDiagnostic(DiagnosticId.SEC0018)]
    public class PasswordLockoutAnalyzer : ISyntaxNodeAnalyzer
    {
        public SyntaxKind Kind => SyntaxKind.InvocationExpression;

        public IEnumerable<DiagnosticInfo> GetDiagnosticInfo(SyntaxNodeAnalysisContext context)
        {
            var result = new List<DiagnosticInfo>();
            var statement = context.Node as InvocationExpressionSyntax;
            var expression = statement.Expression as MemberAccessExpressionSyntax;

            var isMethod = expression?.Name.ToString().StartsWith("PasswordSignIn", StringComparison.Ordinal);
            if(!isMethod.HasValue || !isMethod.Value)
                return result;

            var symbol = context.SemanticModel.GetSymbolInfo(expression).Symbol as ISymbol;
            if (string.Compare(symbol?.ContainingNamespace.ToString(), "Microsoft.AspNet.Identity.Owin", StringComparison.Ordinal) != 0)
                return result;

            var args = statement.ArgumentList as ArgumentListSyntax;
            if (args == null || args.Arguments.Count < 4)
                return result;

            var passwordLockoutParm = args.Arguments[3];
            var argExpression = passwordLockoutParm.Expression as LiteralExpressionSyntax;

            if (argExpression == null)
                return result;

            var token = context.SemanticModel.GetConstantValue(argExpression);

            if (token.HasValue && !(bool)token.Value)
                result.Add(new DiagnosticInfo(argExpression.GetLocation()));

            return result;
        }
    }
}
