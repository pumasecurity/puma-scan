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

using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Common.Extensions;

namespace Puma.Security.Rules.Analyzer.Injection.Ldap.Core
{
    public class LdapDirectoryEntryPathInjectionExpressionAnalyzer : ILdapDirectoryEntryPathInjectionExpressionAnalyzer
    {
        public bool IsVulnerable(SemanticModel model, ObjectCreationExpressionSyntax syntax)
        {
            if (!syntax.ToString().Contains("DirectoryEntry")) return false;

            var symbol = model.GetSymbolInfo(syntax).Symbol as IMethodSymbol;
            if (symbol.IsCtorFor("System.DirectoryServices.DirectoryEntry"))
            {
                if (syntax.ArgumentList?.Arguments.Count > 0)
                {
                    var argSyntax = syntax.ArgumentList.Arguments[0].Expression;
                    var expressionAnalyzer = ExpressionSyntaxAnalyzerFactory.Create(argSyntax);
                    if (expressionAnalyzer.CanSuppress(model, argSyntax))
                    {
                        return false;
                    }
                }

                var filter = syntax.Initializer?.Expressions.OfType<AssignmentExpressionSyntax>()
                    .FirstOrDefault(p => (p.Left as IdentifierNameSyntax)?.Identifier.ValueText == "Path");

                if (filter != null)
                {
                    var expressionAnalyzer = ExpressionSyntaxAnalyzerFactory.Create(filter.Right);
                    if (expressionAnalyzer.CanSuppress(model, filter.Right))
                    {
                        return false;
                    }
                }

                if (filter == null && syntax.ArgumentList?.Arguments.Count == 0)
                {
                    return false;
                }

                return true;
            }

            return false;
        }
    }
}