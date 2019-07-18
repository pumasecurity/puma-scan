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

namespace Puma.Security.Rules.Analyzer.Injection.Deserialization.Core
{
    internal class NewtonsoftJsonTypeNameHandlingExpressionAnalyzer : INewtonsoftJsonTypeNameHandlingExpressionAnalyzer
    {
        public bool IsVulnerable(SemanticModel model, AssignmentExpressionSyntax syntax, DiagnosticId ruleId)
        {
            //2 cases here: x.TypeNameHandling or { TypeNameHandling = }
            if (syntax?.Left is MemberAccessExpressionSyntax)
            {
                var leftSyntax = syntax?.Left as MemberAccessExpressionSyntax;
                if (leftSyntax == null || string.Compare(leftSyntax.Name.Identifier.ValueText, "TypeNameHandling", true) != 0)
                    return false;

                var leftSymbol = model.GetSymbolInfo(leftSyntax.Name).Symbol as IPropertySymbol;
                if (leftSymbol == null || string.Compare(leftSymbol.Type.ToString(), "Newtonsoft.Json.TypeNameHandling", true) != 0)
                    return false;

                var rightSyntax = syntax?.Right as MemberAccessExpressionSyntax;
                if (rightSyntax == null || string.Compare(rightSyntax.Name.Identifier.ValueText, "None", true) == 0)
                    return false;

                return true;
            }
            if (syntax?.Left is IdentifierNameSyntax)
            {
                var leftSyntax = syntax?.Left as IdentifierNameSyntax;
                if (leftSyntax == null || string.Compare(leftSyntax.Identifier.ValueText, "TypeNameHandling", true) != 0)
                    return false;

                var leftSymbol = model.GetSymbolInfo(leftSyntax).Symbol as IPropertySymbol;
                if (leftSymbol == null || string.Compare(leftSymbol.Type.ToString(), "Newtonsoft.Json.TypeNameHandling", true) != 0)
                    return false;

                var rightSyntax = syntax?.Right as MemberAccessExpressionSyntax;
                if (rightSyntax == null || string.Compare(rightSyntax.Name.Identifier.ValueText, "None", true) == 0)
                    return false;

                return true;
            }

            return false;
        }
    }
}