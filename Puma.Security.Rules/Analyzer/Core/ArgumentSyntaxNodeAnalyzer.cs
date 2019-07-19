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
    internal class ArgumentSyntaxNodeAnalyzer : BaseSyntaxNodeAnalyzer<ArgumentSyntax>
    {
        public override bool CanIgnore(SemanticModel model, SyntaxNode syntax)
        {
            var argumentSyntax = syntax as ArgumentSyntax;
            if (argumentSyntax != null)
            {
                var parentOfArgumentSyntaxAnalyzer = SyntaxNodeAnalyzerFactory.Create(argumentSyntax.Parent);
                if (parentOfArgumentSyntaxAnalyzer.CanIgnore(model, argumentSyntax.Parent))
                {
                    return true;
                }
            }

            return base.CanIgnore(model, syntax);
        }

        public override bool CanSuppress(SemanticModel model, SyntaxNode syntax, DiagnosticId ruleId)
        {
            var argumentSyntax = syntax as ArgumentSyntax;
            if (argumentSyntax != null)
            {
                var parentOfArgumentSyntaxAnalyzer = SyntaxNodeAnalyzerFactory.Create(argumentSyntax.Parent);
                if (parentOfArgumentSyntaxAnalyzer.CanSuppress(model, argumentSyntax.Parent, ruleId))
                {
                    return true;
                }
            }

            return base.CanSuppress(model, syntax, ruleId);
        }
    }
}