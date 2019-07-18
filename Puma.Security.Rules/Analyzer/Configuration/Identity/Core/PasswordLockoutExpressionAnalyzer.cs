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
using Puma.Security.Rules.Common.Extensions;

namespace Puma.Security.Rules.Analyzer.Configuration.Identity.Core
{
    internal class PasswordLockoutExpressionAnalyzer : IPasswordLockoutExpressionAnalyzer
    {
        public bool IsVulnerable(SemanticModel model, InvocationExpressionSyntax syntax, out ArgumentSyntax location)
        {
            //Default location object
            location = null;

            var expression = syntax.Expression as MemberAccessExpressionSyntax;
            if (expression == null)
                return false;

            //Check for the name
            if (!ContainsPasswordSignIn(expression)) return false;

            //If we found it, verify the namespace
            var symbol = model.GetSymbolInfo(expression).Symbol as IMethodSymbol;

            if (IsMvcType(symbol))
            {
                var args = syntax.ArgumentList;
                if (args == null || args.Arguments.Count < 4)
                    return false;

                var passwordLockoutParm = args.Arguments[3];
                if (passwordLockoutParm.Expression.IsFalse())
                {
                    location = passwordLockoutParm;
                    return true;
                }
            }

            if (IsCoreType(symbol))
            {
                //Two options: PasswordSignInAsync (parm[3]) and CheckPasswordSignInAsync (parm[2]). Both
                //are the last parameter
                var args = syntax.ArgumentList;
                if (args == null)
                    return false;

                var passwordLockoutParm = args.Arguments.Last();
                if (passwordLockoutParm.Expression.IsFalse())
                {
                    location = passwordLockoutParm;
                    return true;
                }
            }

            return false;
        }

        private static bool ContainsPasswordSignIn(MemberAccessExpressionSyntax syntax)
        {
            //OWIN: PasswordSignIn, Core: CheckPasswordSignIn
            return syntax.Name.ToString().Contains("PasswordSignIn");
        }

        private bool IsMvcType(IMethodSymbol symbol)
        {
            return symbol.DoesMethodContain("Microsoft.AspNet.Identity.Owin", "PasswordSignIn", true);
        }

        private bool IsCoreType(IMethodSymbol symbol)
        {
            return symbol.DoesMethodContain("Microsoft.AspNetCore.Identity", "PasswordSignIn", true);
        }
    }
}