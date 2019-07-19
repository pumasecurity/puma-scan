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

using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

using Puma.Security.Rules.Analyzer.Configuration.Identity.Core;
using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Analyzer.Core.Factories;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Diagnostics;

namespace Puma.Security.Rules.Analyzer.Configuration.Identity
{
    [SupportedDiagnostic(DiagnosticId.SEC0018)]
    internal class PasswordLockoutAnalyzer : BaseSemanticAnalyzer, ISyntaxAnalyzer
    {
        private readonly IPasswordLockoutExpressionAnalyzer _expressionSyntaxAnalyzer;
        private readonly IArgumentVulnerableSyntaxNodeFactory _vulnerableSyntaxNodeFactory;

        internal PasswordLockoutAnalyzer() : this(new PasswordLockoutExpressionAnalyzer(), new ArgumentVulnerableSyntaxNodeFactory()) { }

        private PasswordLockoutAnalyzer(IPasswordLockoutExpressionAnalyzer expressionSyntaxAnalyzer,
            IArgumentVulnerableSyntaxNodeFactory vulnerableSyntaxNodeFactory)
        {
            _expressionSyntaxAnalyzer = expressionSyntaxAnalyzer;
            _vulnerableSyntaxNodeFactory = vulnerableSyntaxNodeFactory;
        }

        public SyntaxKind SinkKind => SyntaxKind.InvocationExpression;

        public override void GetSinks(SyntaxNodeAnalysisContext context, DiagnosticId ruleId)
        {
            var syntax = context.Node as InvocationExpressionSyntax;

            ArgumentSyntax argumentSyntaxStatement = null;
            if (!_expressionSyntaxAnalyzer.IsVulnerable(context.SemanticModel, syntax, out argumentSyntaxStatement))
                return;

            if (VulnerableSyntaxNodes.All(p => p.Sink.GetLocation() != argumentSyntaxStatement.GetLocation()))
                VulnerableSyntaxNodes.Push(_vulnerableSyntaxNodeFactory.Create(argumentSyntaxStatement));
        }
    }
}