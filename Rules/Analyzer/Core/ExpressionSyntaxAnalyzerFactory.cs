/* 
 * Copyright(c) 2016 Puma Security, LLC (https://www.pumascan.com)
 * 
 * Project Leader: Eric Johnson (eric.johnson@pumascan.com)
 * Lead Developer: Eric Mead (eric.mead@pumascan.com)
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Puma.Security.Rules.Analyzer.Core
{
    public static class ExpressionSyntaxAnalyzerFactory
    {
        public static IExpressionSyntaxAnalyzer Create(ExpressionSyntax syntax)
        {
            var factory = PumaApp.Instance.GetFuncFactory<IExpressionSyntaxAnalyzer>();

            return factory(syntax);
        }
    }
}