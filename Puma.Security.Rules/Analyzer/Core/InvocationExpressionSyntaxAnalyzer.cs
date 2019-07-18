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

using System.Linq;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Analyzer.Core.Specialized;
using Puma.Security.Rules.Common;

namespace Puma.Security.Rules.Analyzer.Core
{
    internal class InvocationExpressionSyntaxAnalyzer : BaseSyntaxNodeAnalyzer<InvocationExpressionSyntax>
    {
        private readonly ISanitizedSourceAnalyzer _sanitizedSourceAnalyzer;
        private readonly ISyntaxNodeAnalyzer<SyntaxNode> _analyzer;
        private readonly IIsArgumentOnlyExpression _argsOnlyInvocationExpression;

        internal InvocationExpressionSyntaxAnalyzer() 
            : this(new SanitizedSourceAnalyzer(),
                  new IsArgumentOnlyExpression(),
                  new SyntaxNodeAnalyzer()) 
        {
            
        }

        internal InvocationExpressionSyntaxAnalyzer(ISanitizedSourceAnalyzer sanitizedSourceAnalyzer, IIsArgumentOnlyExpression argsOnlyInvocationExpression, ISyntaxNodeAnalyzer<SyntaxNode> syntaxNodeAnalyzer)
        {
            _sanitizedSourceAnalyzer = sanitizedSourceAnalyzer;
            _argsOnlyInvocationExpression = argsOnlyInvocationExpression;
            _analyzer = syntaxNodeAnalyzer;
        }

        public override bool CanSuppress(SemanticModel model, SyntaxNode syntax, DiagnosticId ruleId)
        {
            var invocationExpressionSyntax = syntax as InvocationExpressionSyntax;

            if (_sanitizedSourceAnalyzer.IsSymbolSanitized(model.GetSymbolInfo(invocationExpressionSyntax), ruleId))
                return true;

            var argsSafe = CanSuppressArguments(model, invocationExpressionSyntax.ArgumentList, ruleId);

            var isArgsOnlyExpression = _argsOnlyInvocationExpression.Execute(model, invocationExpressionSyntax);

            if (isArgsOnlyExpression)
                return argsSafe;

            var isBodySafe = CanSuppressExpression(model, invocationExpressionSyntax.Expression, ruleId);

            return argsSafe && isBodySafe;
        }

        private bool CanSuppressExpression(SemanticModel model, SyntaxNode expression, DiagnosticId ruleId)
        {
            return _analyzer.CanIgnore(model, expression) || _analyzer.CanSuppress(model, expression, ruleId);
        }

        private bool CanSuppressArguments(SemanticModel model, ArgumentListSyntax argumentList, DiagnosticId ruleId)
        {
            if (!argumentList.Arguments.Any())
                return true;

            var args = argumentList.Arguments;

            return args.All(p => _analyzer.CanIgnore(model, p.Expression) || _analyzer.CanSuppress(model, p.Expression, ruleId));
        }
    }
}