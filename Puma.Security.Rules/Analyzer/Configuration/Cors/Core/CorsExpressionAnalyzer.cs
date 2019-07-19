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
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Common.Extensions;

namespace Puma.Security.Rules.Analyzer.Configuration.Cors.Core
{
    internal class CorsExpressionAnalyzer : ICorsExpressionAnalyzer
    {
        public bool IsVulnerable(SemanticModel model, MemberAccessExpressionSyntax syntax, DiagnosticId ruleId)
        {
            //Quick check for the object name
            if (!IsTypeName(syntax)) return false;

            //Verify full namesapce
            var symbol = model.GetSymbolInfo(syntax).Symbol as IMethodSymbol;
            if (!symbol.IsMethod("Microsoft.AspNetCore.Cors.Infrastructure.CorsPolicyBuilder", "AllowAnyOrigin"))
                return false;

            return true;
        }

        private static bool IsTypeName(MemberAccessExpressionSyntax syntax)
        {
            return syntax.Name.ToString().Equals("AllowAnyOrigin");
        }

        private bool IsType(ISymbol symbol)
        {
            if (symbol == null)
                return false;

            return symbol.ContainingNamespace.ToString().Equals("Microsoft.AspNetCore.Cors.Infrastructure");
        }
    }
}
