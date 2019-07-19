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

using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Puma.Security.Rules.Analyzer.AccessControl.Jwt.Core;
using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Diagnostics;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Puma.Security.Rules.Analyzer.AccessControl.Jwt
{
    [SupportedDiagnostic(DiagnosticId.SEC0122)]
    internal class JwtSignatureAnalyzer : BaseSemanticAnalyzer, ISyntaxAnalyzer
    {
        private readonly IJwtSignatureExpressionAnalyzer _expressionSyntaxAnalyzer;

        internal JwtSignatureAnalyzer() : this(new JwtSignatureExpressionAnalyzer()) { }

        private JwtSignatureAnalyzer(IJwtSignatureExpressionAnalyzer expressionSyntaxAnalyzer)
        {
            _expressionSyntaxAnalyzer = expressionSyntaxAnalyzer;
        }

        public SyntaxKind SinkKind => SyntaxKind.SimpleAssignmentExpression;

        public override void GetSinks(SyntaxNodeAnalysisContext context, DiagnosticId ruleId)
        {
            if (context.Node is AssignmentExpressionSyntax syntax)
            {
                if (!_expressionSyntaxAnalyzer.IsVulnerable(context.SemanticModel, syntax, ruleId))
                    return;

                if (VulnerableSyntaxNodes.All(p => p.Sink.GetLocation() != syntax.GetLocation()))
                    VulnerableSyntaxNodes.Push(new VulnerableSyntaxNode(syntax));
            }
        }
    }
}
