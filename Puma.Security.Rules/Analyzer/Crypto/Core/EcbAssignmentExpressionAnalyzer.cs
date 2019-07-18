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

using Puma.Security.Rules.Common;

namespace Puma.Security.Rules.Analyzer.Crypto.Core
{
    internal class EcbAssignmentExpressionAnalyzer : IEcbAssignmentExpressionAnalyzer
    {
        public bool IsVulnerable(SemanticModel model, AssignmentExpressionSyntax syntax, DiagnosticId ruleId)
        {
            var leftSyntax = syntax?.Left as MemberAccessExpressionSyntax;
            if (leftSyntax == null || string.Compare(leftSyntax.Name.Identifier.ValueText, "Mode", true) != 0)
                return false;

            var leftSymbol = model.GetSymbolInfo(leftSyntax.Name).Symbol as IPropertySymbol;
            if (leftSymbol == null || string.Compare(leftSymbol.Type.ToString(), "System.Security.Cryptography.CipherMode", true) != 0)
                return false;

            var rightSyntax = syntax?.Right as MemberAccessExpressionSyntax;
            if (rightSyntax == null || string.Compare(rightSyntax.Name.Identifier.ValueText, "ECB", true) != 0)
                return false;

            var rightSymbol = model.GetSymbolInfo(rightSyntax.Name).Symbol as IFieldSymbol;
            if (rightSyntax == null || string.Compare(rightSymbol.OriginalDefinition.ToString(), "System.Security.Cryptography.CipherMode.ECB", true) != 0)
                return false;

            return true;
        }
    }
}