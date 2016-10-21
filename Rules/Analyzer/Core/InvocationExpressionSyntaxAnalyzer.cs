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

using System.Linq;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Analyzer.Core.Specialized;

namespace Puma.Security.Rules.Analyzer.Core
{
    public class InvocationExpressionSyntaxAnalyzer : BaseExpressionSyntaxAnalyzer<InvocationExpressionSyntax>
    {
        private readonly IXssSafeInvocationExpression _safeInvocationExpression;
        private readonly IExpressionSyntaxAnalyzer<ExpressionSyntax> _analyzer;
        private readonly IsArgumentOnlyExpression _argsOnlyInvocationExpression;

        public InvocationExpressionSyntaxAnalyzer()
        {
            _safeInvocationExpression = new XssSafeInvocationExpression();
            _argsOnlyInvocationExpression = new IsArgumentOnlyExpression();
            _analyzer = new ExpressionSyntaxAnalyzer();
        }

        public override bool CanSuppress(SemanticModel model, ExpressionSyntax syntax)
        {
            var invocationExpressionSyntax = syntax as InvocationExpressionSyntax;

            if (_safeInvocationExpression.IsSafe(model, invocationExpressionSyntax))
                return true;

            var argsSafe = CanSuppressArguments(model, invocationExpressionSyntax.ArgumentList);

            var isArgsOnlyExpression = _argsOnlyInvocationExpression.Execute(model, invocationExpressionSyntax);

            if(isArgsOnlyExpression)
                return argsSafe;

            var isBodySafe = CanSuppressExpression(model, invocationExpressionSyntax.Expression);

            return argsSafe && isBodySafe;
        }
        
        private bool CanSuppressExpression(SemanticModel model, ExpressionSyntax expression)
        {
            return _analyzer.CanSuppress(model, expression);
        }

        private bool CanSuppressArguments(SemanticModel model, ArgumentListSyntax argumentList)
        {
            if (!argumentList.Arguments.Any())
                return true;

            var args = argumentList.Arguments;

            return args.All(p => _analyzer.CanSuppress(model, p.Expression));
        }
    }
}