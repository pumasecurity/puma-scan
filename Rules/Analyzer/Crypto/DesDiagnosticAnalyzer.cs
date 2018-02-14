/* 
 * Copyright(c) 2016 - 2017 Puma Security, LLC (https://www.pumascan.com)
 * 
 * Project Leader: Eric Johnson (eric.johnson@pumascan.com)
 * Lead Developer: Eric Mead (eric.mead@pumascan.com)
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

using System.Collections.Generic;

using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

using Puma.Security.Rules.Analyzer.Crypto.Core;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Diagnostics;
using Puma.Security.Rules.Model;

namespace Puma.Security.Rules.Analyzer.Crypto
{
    [SupportedDiagnostic(DiagnosticId.SEC0025)]
    public class DesDiagnosticAnalyzer : ISyntaxNodeAnalyzer
    {
        private readonly IDesExpressionAnalzyer _expressionSyntaxAnalyzer;

        public DesDiagnosticAnalyzer(IDesExpressionAnalzyer expressionSyntaxAnalyzer)
        {
            _expressionSyntaxAnalyzer = expressionSyntaxAnalyzer;
        }

        public SyntaxKind Kind => SyntaxKind.ObjectCreationExpression;

        public IEnumerable<DiagnosticInfo> GetDiagnosticInfo(SyntaxNodeAnalysisContext context)
        {
            var result = new List<DiagnosticInfo>();
            var syntax = context.Node as ObjectCreationExpressionSyntax;

            if (!_expressionSyntaxAnalyzer.IsVulnerable(context.SemanticModel, syntax))
                return result;

            result.Add(new DiagnosticInfo(syntax.GetLocation()));

            return result;
        }
    }
}
