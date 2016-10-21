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

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Puma.Security.Rules.Analyzer.Core
{
    public class BinaryExpressionSyntaxAnalyzer : BaseExpressionSyntaxAnalyzer<BinaryExpressionSyntax>
    {
        private readonly IExpressionSyntaxAnalyzer<ExpressionSyntax> _analyzer;

        public BinaryExpressionSyntaxAnalyzer()
        {
            _analyzer = new ExpressionSyntaxAnalyzer();
        }

        public override bool CanSuppress(SemanticModel model, ExpressionSyntax syntax)
        {
            var binaryExpressionSyntax = syntax as BinaryExpressionSyntax;

            return _analyzer.CanSuppress(model, binaryExpressionSyntax.Right) &&
                   _analyzer.CanSuppress(model, binaryExpressionSyntax.Left);
        }
    }
}