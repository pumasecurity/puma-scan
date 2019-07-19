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
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Puma.Security.Rules.Analyzer.AccessControl.Authorize.Core;
using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Diagnostics;
using System.Linq;

namespace Puma.Security.Rules.Analyzer.AccessControl.Authorize
{
    [SupportedDiagnostic(DiagnosticId.SEC0120)]
    internal class AuthorizeAnalyzer : BaseSemanticAnalyzer, ISyntaxAnalyzer
    {
        private readonly IAuthorizeExpressionAnalyzer _mvcCoreAuthorizeExpressionAnalyzer;

        internal AuthorizeAnalyzer() : this(new MvcCoreAuthorizeExpressionAnalyzer()) { }

        private AuthorizeAnalyzer(IAuthorizeExpressionAnalyzer mvcCoreAuthorizeExpressionAnalyzer)
        {
            _mvcCoreAuthorizeExpressionAnalyzer = mvcCoreAuthorizeExpressionAnalyzer;
        }

        public SyntaxKind SinkKind => SyntaxKind.ClassDeclaration;

        public override void GetSinks(SyntaxNodeAnalysisContext context, DiagnosticId ruleId)
        {
            var syntax = context.Node as ClassDeclarationSyntax;

            foreach (SyntaxNode node in _mvcCoreAuthorizeExpressionAnalyzer.IsVulnerable(context.SemanticModel, syntax))
            {
                if (VulnerableSyntaxNodes.All(p => p.Sink.GetLocation() != node.GetLocation()))
                    VulnerableSyntaxNodes.Push(new VulnerableSyntaxNode(node));
            }
        }
    }
}
