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

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Common.Extensions;

namespace Puma.Security.Rules.Analyzer.Core.Specialized
{
    internal interface IIsArgumentOnlyExpression
    {
        bool Execute(SemanticModel model, InvocationExpressionSyntax syntax);
    }

    internal class IsArgumentOnlyExpression : IIsArgumentOnlyExpression
    {
        public bool Execute(SemanticModel model, InvocationExpressionSyntax syntax)
        {
            if (ContainsArgumentOnlyMethod(syntax))
            {
                var symbol = model.GetSymbolInfo(syntax).Symbol as IMethodSymbol;
                if (symbol != null)
                {
                    return IsArgumentOnlyMethod(symbol);
                }
            }

            return false;
        }
        
        private bool IsArgumentOnlyMethod(IMethodSymbol symbol)
        {
            return symbol.IsMethod("System.Web.HttpRequest", "MapPath") ||
                   symbol.IsMethod("String", "Format");
        }

        private static bool ContainsArgumentOnlyMethod(InvocationExpressionSyntax syntax)
        {
            return syntax.ToString().Contains("Format") ||
                   syntax.ToString().Contains("MapPath");
        }
    }
}