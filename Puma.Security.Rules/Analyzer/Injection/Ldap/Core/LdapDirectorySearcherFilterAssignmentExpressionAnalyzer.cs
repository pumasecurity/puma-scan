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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Common;

namespace Puma.Security.Rules.Analyzer.Injection.Ldap.Core
{
    internal class LdapDirectorySearcherFilterAssignmentExpressionAnalyzer : ILdapDirectorySearcherFilterAssignmentExpressionAnalyzer
    {
        public bool IsVulnerable(SemanticModel model, AssignmentExpressionSyntax syntax, DiagnosticId ruleId)
        {
            var leftSyntax = syntax?.Left as MemberAccessExpressionSyntax;

            if (leftSyntax == null)
                return false;

            if (string.Compare(leftSyntax.Name.Identifier.ValueText, "Filter", StringComparison.OrdinalIgnoreCase) != 0)
                return false;

            var leftSymbol = model.GetSymbolInfo(leftSyntax).Symbol;

            if (leftSymbol == null)
                return false;

            if (!leftSymbol.ToString().StartsWith("System.DirectoryServices.DirectorySearcher"))
                return false;

            var expressionAnalyzer = SyntaxNodeAnalyzerFactory.Create(syntax.Right);
            if (expressionAnalyzer.CanIgnore(model, syntax.Right))
                return false;
            if (expressionAnalyzer.CanSuppress(model, syntax.Right, ruleId))
                return false;

            return true;
        }
    }
}
