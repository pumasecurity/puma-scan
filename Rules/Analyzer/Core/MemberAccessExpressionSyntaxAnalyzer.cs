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

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Analyzer.Core.Specialized;
using Puma.Security.Rules.Common;

namespace Puma.Security.Rules.Analyzer.Core
{
    public class MemberAccessExpressionSyntaxAnalyzer : BaseExpressionSyntaxAnalyzer<MemberAccessExpressionSyntax>
    {
        public override bool CanSuppress(SemanticModel model, ExpressionSyntax syntax)
        {
            var memberAccessExpressionSyntax = syntax as MemberAccessExpressionSyntax;
            var symbol = model.GetSymbolInfo(memberAccessExpressionSyntax).Symbol as IMethodSymbol;

            if (symbol == null) return base.CanSuppress(model, syntax);

            if (symbol.ToString().StartsWith("string.format", StringComparison.InvariantCultureIgnoreCase) && !symbol.IsOverride)
                return true;

            if (Utils.IsXssWhiteListedType(symbol.ReceiverType))
                return true;
          
            return false;
        }
    }
}