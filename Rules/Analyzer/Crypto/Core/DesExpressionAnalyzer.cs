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

using System;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Puma.Security.Rules.Analyzer.Crypto.Core
{
    internal class DesExpressionAnalyzer : IDesExpressionAnalzyer
    {
        public bool IsVulnerable(SemanticModel model, ObjectCreationExpressionSyntax syntax)
        {
            //Check for the type
            if (!ContainsTypeName(syntax)) return false;

            //If we found it, verify the namespace
            var symbol = model.GetSymbolInfo(syntax).Symbol;

            if (!IsType(symbol)) return false;

            return true;
        }

        private static bool ContainsTypeName(ObjectCreationExpressionSyntax syntax)
        {
            return string.Compare(syntax?.Type.ToString(), "DESCryptoServiceProvider", StringComparison.Ordinal) == 0;
        }

        private bool IsType(ISymbol symbol)
        {
            return symbol.ContainingNamespace.ToString().Equals("System.Security.Cryptography");
        }
    }
}