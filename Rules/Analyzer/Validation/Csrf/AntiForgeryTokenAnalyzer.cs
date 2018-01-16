/* 
 * Copyright(c) 2016 - 2018 Puma Security, LLC (https://www.pumascan.com)
 * 
 * Project Leader: Eric Johnson (eric.johnson@pumascan.com)
 * Lead Developer: Eric Mead (eric.mead@pumascan.com)
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

using System.Linq;

using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Analyzer.Core.Factories;
using Puma.Security.Rules.Analyzer.Validation.Csrf.Core;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Diagnostics;

namespace Puma.Security.Rules.Analyzer.Validation.Csrf
{
    [SupportedDiagnostic(DiagnosticId.SEC0019)]
    internal class AntiForgeryTokenAnalyzer : BaseSemanticAnalyzer, ISyntaxAnalyzer
    {
        private readonly IAntiForgeryTokenExpressionAnalyzer _expressionSyntaxAnalyzer;
        private readonly IIdentifierNameVulnerableSyntaxNodeFactory _vulnerableSyntaxNodeFactory;

        internal AntiForgeryTokenAnalyzer() : this(new AntiForgeryTokenExpressionAnalyzer(), new IdentifierNameVulnerableSyntaxNodeFactory()) { }

        private AntiForgeryTokenAnalyzer(IAntiForgeryTokenExpressionAnalyzer expressionSyntaxAnalyzer,
            IIdentifierNameVulnerableSyntaxNodeFactory vulnerableSyntaxNodeFactory)
        {
            _expressionSyntaxAnalyzer = expressionSyntaxAnalyzer;
            _vulnerableSyntaxNodeFactory = vulnerableSyntaxNodeFactory;
        }

        public SyntaxKind SinkKind => SyntaxKind.MethodDeclaration;

        public override void GetSinks(SyntaxNodeAnalysisContext context)
        {
            var syntax = context.Node as MethodDeclarationSyntax;

            //Grab the method's return type for the location value
            var returnType = Utils.GetMethodReturnType(syntax);

            if (!_expressionSyntaxAnalyzer.IsVulnerable(context.SemanticModel, syntax, returnType))
                return;

            if (VulnerableSyntaxNodes.All(p => p.Sink.GetLocation() != returnType?.GetLocation()))
                VulnerableSyntaxNodes.Push(_vulnerableSyntaxNodeFactory.Create(returnType));
        }
    }
}