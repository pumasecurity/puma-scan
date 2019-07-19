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

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Puma.Security.Rules.Analyzer.Validation.RequestValidation.Core
{
    internal class ValidateInputExpressionAnalyzer : IValidateInputExpressionAnalyzer
    {
        public bool IsVulnerable(SemanticModel model, AttributeSyntax syntax)
        {
            //Check the type name
            if (!ContainsTypeName(syntax)) return false;

            //If we found it, verify the namespace
            var symbol = model.GetSymbolInfo(syntax).Symbol;
            if (!IsType(symbol)) return false;

            //Verify the first argument is false (i.e. disabled)            
            var argumentList = syntax.ArgumentList;
            var argument = argumentList.Arguments.First();
            var value = model.GetConstantValue(argument?.Expression);

            return value.HasValue && (bool) value.Value == false;
        }

        private static bool ContainsTypeName(AttributeSyntax syntax)
        {
            return string.Compare(syntax?.Name.ToString(), "ValidateInput", StringComparison.Ordinal) == 0;
        }

        private bool IsType(ISymbol symbol)
        {
            if (symbol == null)
                return false;

            return string.Compare(symbol.ContainingNamespace.ToString(), "System.Web.Mvc") == 0;
        }
    }
}