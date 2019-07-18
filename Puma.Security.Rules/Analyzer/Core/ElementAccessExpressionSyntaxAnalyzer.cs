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

using System.Configuration;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Common;

namespace Puma.Security.Rules.Analyzer.Core
{
    internal class ElementAccessExpressionSyntaxAnalyzer : BaseSyntaxNodeAnalyzer<ElementAccessExpressionSyntax>
    {
        public override bool CanIgnore(SemanticModel model, SyntaxNode syntax)
        {
            var elementAccessExpressionSyntax = syntax as ElementAccessExpressionSyntax;

            if (elementAccessExpressionSyntax != null)
            {
                var elementAccessExpressionExpressionSyntax = SyntaxNodeAnalyzerFactory.Create(elementAccessExpressionSyntax.Expression);
                if (elementAccessExpressionExpressionSyntax.CanIgnore(model, elementAccessExpressionSyntax.Expression))
                {
                    return true;
                }
            }

            return false;
        }

        public override bool CanSuppress(SemanticModel model, SyntaxNode syntax, DiagnosticId ruleId)
        {
            var elementAccessExpressionSyntax = syntax as ElementAccessExpressionSyntax;

            if (elementAccessExpressionSyntax != null)
            {
                var elementAccessExpressionExpressionSyntax = SyntaxNodeAnalyzerFactory.Create(elementAccessExpressionSyntax.Expression);
                if (elementAccessExpressionExpressionSyntax.CanSuppress(model, elementAccessExpressionSyntax.Expression, ruleId))
                {
                    return true;
                }
            }

            return false;
        }
    }
}