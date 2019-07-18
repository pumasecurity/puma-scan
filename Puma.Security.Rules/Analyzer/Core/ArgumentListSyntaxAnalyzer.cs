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
    internal class ArgumentListSyntaxAnalyzer : BaseSyntaxNodeAnalyzer<ArgumentListSyntax>
    {
        public override bool CanIgnore(SemanticModel model, SyntaxNode syntax)
        {
            var argumentListSyntax = syntax as ArgumentListSyntax;
            if (argumentListSyntax != null)
            {
                var parentOfArgumentListSyntaxAnalyzer = SyntaxNodeAnalyzerFactory.Create(argumentListSyntax.Parent);
                if (parentOfArgumentListSyntaxAnalyzer.CanIgnore(model, argumentListSyntax.Parent))
                {
                    return true;
                }
            }

            return base.CanIgnore(model, syntax);
        }

        public override bool CanSuppress(SemanticModel model, SyntaxNode syntax, DiagnosticId ruleId)
        {
            var argumentListSyntax = syntax as ArgumentListSyntax;
            if (argumentListSyntax != null)
            {
                var parentOfArgumentListSyntaxAnalyzer = SyntaxNodeAnalyzerFactory.Create(argumentListSyntax.Parent);
                if (parentOfArgumentListSyntaxAnalyzer.CanSuppress(model, argumentListSyntax.Parent, ruleId))
                {
                    return true;
                }
            }

            return base.CanSuppress(model, syntax, ruleId);
        }
    }
}