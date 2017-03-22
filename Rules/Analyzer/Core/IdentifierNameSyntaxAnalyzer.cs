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
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Common;

namespace Puma.Security.Rules.Analyzer.Core
{
    public class IdentifierNameSyntaxAnalyzer : BaseExpressionSyntaxAnalyzer<IdentifierNameSyntax>
    {
        public override bool CanSuppress(SemanticModel model, ExpressionSyntax syntax)
        {
            var identifierNameSyntax = syntax as IdentifierNameSyntax;
            var symbolInfo = model.GetSymbolInfo(identifierNameSyntax);

            var methodSymbol = symbolInfo.Symbol as IMethodSymbol;
            if (methodSymbol != null && Utils.IsXssWhiteListedType(methodSymbol.ReturnType))
                return true;

            var localSymbol = symbolInfo.Symbol as ILocalSymbol;
            if (localSymbol != null && Utils.IsXssWhiteListedType(localSymbol.Type))
                return true;

            //todo: IParameterSymbol, IFieldSymbol, IPropertySymbol <- potential false postives to remove base on type, if string then need data flow analysis

            return false;
        }
    }
}