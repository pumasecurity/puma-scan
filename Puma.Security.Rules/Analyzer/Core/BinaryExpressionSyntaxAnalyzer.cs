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
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Common;

namespace Puma.Security.Rules.Analyzer.Core
{
    internal class BinaryExpressionSyntaxAnalyzer : BaseSyntaxNodeAnalyzer<BinaryExpressionSyntax>
    {
        private readonly ISyntaxNodeAnalyzer<SyntaxNode> _analyzer;

        internal BinaryExpressionSyntaxAnalyzer()
        {
            _analyzer = new SyntaxNodeAnalyzer();
        }

        public override bool CanIgnore(SemanticModel model, SyntaxNode syntax)
        {
            var binaryExpressionSyntax = syntax as BinaryExpressionSyntax;

            return _analyzer.CanIgnore(model, binaryExpressionSyntax.Right) &&
                   _analyzer.CanIgnore(model, binaryExpressionSyntax.Left);
        }

        public override bool CanSuppress(SemanticModel model, SyntaxNode syntax, DiagnosticId ruleId)
        {
            var binaryExpressionSyntax = syntax as BinaryExpressionSyntax;

            return _analyzer.CanSuppress(model, binaryExpressionSyntax.Right, ruleId) &&
                   _analyzer.CanSuppress(model, binaryExpressionSyntax.Left, ruleId);
        }
    }
}