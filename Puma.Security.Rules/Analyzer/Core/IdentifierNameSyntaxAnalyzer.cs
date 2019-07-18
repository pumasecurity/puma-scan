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
    internal class IdentifierNameSyntaxAnalyzer : BaseSyntaxNodeAnalyzer<IdentifierNameSyntax>
    {
        private readonly ISanitizedSourceAnalyzer _sanitizedSourceAnalyzer;
        private readonly ISafeSyntaxTypeAnalyzer _safeSyntaxTypeAnalyzer;

        internal IdentifierNameSyntaxAnalyzer()
            : this(
                  new SanitizedSourceAnalyzer(),
                  new SafeSyntaxTypeAnalyzer())
        {

        }

        internal IdentifierNameSyntaxAnalyzer(ISanitizedSourceAnalyzer sanitizedSourceAnalyzer, ISafeSyntaxTypeAnalyzer safeSyntaxTypeAnalyzer)
        {
            _sanitizedSourceAnalyzer = sanitizedSourceAnalyzer;
            _safeSyntaxTypeAnalyzer = safeSyntaxTypeAnalyzer;
        }

        public override bool CanIgnore(SemanticModel model, SyntaxNode syntax)
        {
            var identifierNameSyntax = syntax as IdentifierNameSyntax;
            var symbolInfo = model.GetSymbolInfo(identifierNameSyntax);

            if (_safeSyntaxTypeAnalyzer.IsSafeSyntaxType(symbolInfo))
                return true;

            return base.CanIgnore(model, syntax);
        }

        public override bool CanSuppress(SemanticModel model, SyntaxNode syntax, DiagnosticId ruleId)
        {
            var identifierNameSyntax = syntax as IdentifierNameSyntax;
            var symbolInfo = model.GetSymbolInfo(identifierNameSyntax);

            if (_sanitizedSourceAnalyzer.IsSymbolSanitized(symbolInfo, ruleId))
                return true;

            return base.CanSuppress(model, syntax, ruleId);
        }
    }
}