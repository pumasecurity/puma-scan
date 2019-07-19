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
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Common;

namespace Puma.Security.Rules.Analyzer.Core
{
    internal class ParameterSyntaxNodeAnalyzer : BaseSyntaxNodeAnalyzer<ParameterSyntax>
    {
        private readonly ISanitizedParameterSymbolAnalyzer _sanitizedSourceAnalyzer;
        private readonly ISafeSyntaxTypeAnalyzer _safeSyntaxTypeAnalyzer;

        internal ParameterSyntaxNodeAnalyzer() :
            this(new CleansedMethodsProvider())
        { }

        internal ParameterSyntaxNodeAnalyzer(ICleansedMethodsProvider cleansedMethodsProvider) 
            :this(new SanitizedParameterSymbolAnalyzer(cleansedMethodsProvider), new SafeSyntaxTypeAnalyzer())
        { }

        internal ParameterSyntaxNodeAnalyzer(ISanitizedParameterSymbolAnalyzer sanitizedSourceAnalyzer, ISafeSyntaxTypeAnalyzer safeSyntaxTypeAnalyzer)
        {
            _sanitizedSourceAnalyzer = sanitizedSourceAnalyzer;
            _safeSyntaxTypeAnalyzer = safeSyntaxTypeAnalyzer;
        }

        public override bool CanIgnore(SemanticModel model, SyntaxNode syntax)
        {
            var parameterSyntax = syntax as ParameterSyntax;
            var symbol = model.GetDeclaredSymbol(parameterSyntax);

            if (_safeSyntaxTypeAnalyzer.IsSafeSyntaxType(symbol.Type)) return true;
            return base.CanIgnore(model, syntax);
        }

        public override bool CanSuppress(SemanticModel model, SyntaxNode syntax, DiagnosticId ruleId)
        {
            var parameterSyntax = syntax as ParameterSyntax;
            var symbol = model.GetDeclaredSymbol(parameterSyntax);

            if (_sanitizedSourceAnalyzer.IsSymbolSanitized(symbol, ruleId)) return true;
            return base.CanSuppress(model, syntax, ruleId);
        }
    }
}