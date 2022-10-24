/* 
 * Copyright(c) 2016 - 2020 Puma Security, LLC (https://pumasecurity.io)
 * 
 * Project Leads:
 * Eric Johnson (eric.johnson@pumascan.com)
 * Eric Mead (eric.mead@pumascan.com)
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Common.Extensions;

namespace Puma.Security.Rules.Analyzer.AccessControl.Jwt.Core
{
    internal class JwtSignatureExpressionAnalyzer : IJwtSignatureExpressionAnalyzer
    {
        public bool IsVulnerable(SemanticModel model, AssignmentExpressionSyntax syntax, DiagnosticId ruleId)
        {
            var leftSyntax = syntax?.Left as IdentifierNameSyntax;
            if (leftSyntax == null || !hasPropertyName(leftSyntax.Identifier.ValueText))
                return false;

            var leftSymbol = model.GetSymbolInfo(leftSyntax).Symbol as ISymbol;
            if (leftSymbol == null || !hasNamespace(leftSymbol))
                return false;

            return syntax.IsFalse(model);
        }

        private bool hasPropertyName(string propertyName)
        {
            return !string.IsNullOrEmpty(propertyName) && ((string.Compare(propertyName, "RequireSignedTokens", true) == 0) || (string.Compare(propertyName, "ValidateIssuerSigningKey", true) == 0));
        }

        private bool hasNamespace(ISymbol symbol)
        {
            if (symbol == null)
                return false;

            return symbol.ContainingNamespace.ToString().Equals("Microsoft.IdentityModel.Tokens");
        }
    }
}
