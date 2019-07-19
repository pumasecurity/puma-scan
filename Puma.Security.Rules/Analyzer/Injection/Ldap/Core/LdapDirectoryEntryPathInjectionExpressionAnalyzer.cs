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
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Common.Extensions;

namespace Puma.Security.Rules.Analyzer.Injection.Ldap.Core
{
    internal class LdapDirectoryEntryPathInjectionExpressionAnalyzer : ILdapDirectoryEntryPathInjectionExpressionAnalyzer
    {
        public bool IsVulnerable(SemanticModel model, ObjectCreationExpressionSyntax syntax, DiagnosticId ruleId)
        {
            if (!syntax.ToString().Contains("DirectoryEntry")) return false;

            var symbol = model.GetSymbolInfo(syntax).Symbol as IMethodSymbol;
            if (symbol.IsCtorFor("System.DirectoryServices.DirectoryEntry"))
            {
                if (syntax.ArgumentList?.Arguments.Count > 0)
                {
                    var argSyntax = syntax.ArgumentList.Arguments[0].Expression;
                    var expressionAnalyzer = SyntaxNodeAnalyzerFactory.Create(argSyntax);
                    if (expressionAnalyzer.CanIgnore(model, argSyntax))
                        return false;
                    if (expressionAnalyzer.CanSuppress(model, argSyntax, ruleId))
                        return false;
                }

                var filter = syntax.Initializer?.Expressions.OfType<AssignmentExpressionSyntax>()
                    .FirstOrDefault(p => (p.Left as IdentifierNameSyntax)?.Identifier.ValueText == "Path");

                if (filter != null)
                {
                    var expressionAnalyzer = SyntaxNodeAnalyzerFactory.Create(filter.Right);
                    if (expressionAnalyzer.CanIgnore(model, filter.Right))
                        return false;
                    if (expressionAnalyzer.CanSuppress(model, filter.Right, ruleId))
                        return false;
                }

                if (filter == null && syntax.ArgumentList?.Arguments.Count == 0)
                    return false;

                return true;
            }

            return false;
        }
    }
}