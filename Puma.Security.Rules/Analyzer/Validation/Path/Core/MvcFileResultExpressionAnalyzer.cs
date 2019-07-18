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

using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Common.Extensions;

namespace Puma.Security.Rules.Analyzer.Validation.Path.Core
{
    internal class MvcFileResultExpressionAnalyzer : IMvcFileResultExpressionAnalyzer
    {
        public SyntaxNode Source { get; set; }

        public bool IsVulnerable(SemanticModel model, ObjectCreationExpressionSyntax syntax, DiagnosticId ruleId)
        {
            if (!containsCommands(syntax))
                return false;

            var symbol = model.GetSymbolInfo(syntax).Symbol as IMethodSymbol;
            if (!isConstructor(symbol))
                return false;

            if (syntax.ArgumentList.Arguments.Count == 0)
                return false;

            var arg = syntax.ArgumentList.Arguments[0].Expression;
            //var argSyntax = arg.Expression;
            var expressionAnalyzer = SyntaxNodeAnalyzerFactory.Create(arg);

            if (expressionAnalyzer.CanIgnore(model, arg))
                return false;

            if (expressionAnalyzer.CanSuppress(model, arg, ruleId))
                return false;

            Source = arg;

            return true;
        }

        private bool containsCommands(ObjectCreationExpressionSyntax syntax)
        {
            return syntax.ToString().Contains("FilePathResult") 
                || syntax.ToString().Contains("FileStreamResult");
        }

        private bool isConstructor(IMethodSymbol symbol)
        {
            return symbol.IsCtorFor("System.Web.Mvc.FilePathResult")
                || symbol.IsCtorFor("System.Web.Mvc.FileStreamResult");
        }
    }
}