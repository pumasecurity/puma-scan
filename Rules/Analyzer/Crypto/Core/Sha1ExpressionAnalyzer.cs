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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Puma.Security.Rules.Common.Extensions;

namespace Puma.Security.Rules.Analyzer.Crypto.Core
{
    public class Sha1ExpressionAnalyzer : ISha1ExpressionAnalzyer
    {
        public bool IsVulnerable(SemanticModel model, ObjectCreationExpressionSyntax syntax)
        {
            //Check for the DESCryptoServiceProvider type
            if (!ContainsTypeName(syntax)) return false;

            //If we found it, verify the namespace
            var symbol = model.GetSymbolInfo(syntax).Symbol as ISymbol;

            if (!IsType(symbol)) return false;

            return true;
        }

        private static bool ContainsTypeName(ObjectCreationExpressionSyntax syntax)
            => string.Compare(syntax?.Type.ToString(), "SHA1CryptoServiceProvider", StringComparison.Ordinal) == 0
            || string.Compare(syntax?.Type.ToString(), "SHA1Managed", StringComparison.Ordinal) == 0;

        private bool IsType(ISymbol symbol) => symbol.ContainingNamespace.ToString().Equals("System.Security.Cryptography");
    }
}
