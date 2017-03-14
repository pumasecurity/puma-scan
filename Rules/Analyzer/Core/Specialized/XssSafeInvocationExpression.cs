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

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Puma.Security.Rules.Analyzer.Core.Specialized
{
    public interface IXssSafeInvocationExpression
    {
        bool IsSafe(SemanticModel model, InvocationExpressionSyntax syntax);
    }

    public class XssSafeInvocationExpression : IXssSafeInvocationExpression
    {
        public bool IsSafe(SemanticModel model, InvocationExpressionSyntax syntax)
        {
            var symbol = model.GetSymbolInfo(syntax).Symbol as IMethodSymbol;
            if (symbol == null)
                return false;

            if (symbol.ToString().StartsWith("System.Web.Security.AntiXss.AntiXssEncoder.HtmlEncode") ||
                symbol.ToString().StartsWith("Microsoft.Security.Application.Encoder.HtmlEncode") ||
                symbol.ToString().StartsWith("System.Web.HttpServerUtility.HtmlEncode"))
                return true;

            return false;
        }
    }
}