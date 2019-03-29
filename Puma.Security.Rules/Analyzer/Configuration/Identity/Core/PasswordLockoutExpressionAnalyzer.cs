/* 
 * Copyright(c) 2016 - 2018 Puma Security, LLC (https://www.pumascan.com)
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

namespace Puma.Security.Rules.Analyzer.Configuration.Identity.Core
{
    internal class PasswordLockoutExpressionAnalyzer : IPasswordLockoutExpressionAnalyzer
    {
        public bool IsVulnerable(SemanticModel model, InvocationExpressionSyntax syntax, out ArgumentSyntax location)
        {
            var expression = syntax.Expression as MemberAccessExpressionSyntax;
            location = null;

            //Check for the name
            if (!ContainsName(expression)) return false;

            //If we found it, verify the namespace
            var symbol = model.GetSymbolInfo(expression).Symbol;
            if (!IsType(symbol)) return false;

            var args = syntax.ArgumentList;
            if (args == null || args.Arguments.Count < 4)
                return false;

            var passwordLockoutParm = args.Arguments[3];
            var argExpression = passwordLockoutParm.Expression as LiteralExpressionSyntax;

            if (argExpression == null)
                return false;

            var token = model.GetConstantValue(argExpression);

            var vulnerable = token.HasValue && !(bool) token.Value;

            if (vulnerable) location = passwordLockoutParm;

            return vulnerable;
        }

        private static bool ContainsName(MemberAccessExpressionSyntax syntax)
        {
            var hasName = syntax?.Name.ToString().StartsWith("PasswordSignIn");
            return hasName.HasValue && hasName.Value;
        }

        private bool IsType(ISymbol symbol)
        {
            if (symbol == null)
                return false;

            return string.Compare(symbol.ContainingNamespace.ToString(), "Microsoft.AspNet.Identity.Owin") == 0;
        }
    }
}