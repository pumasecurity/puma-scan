/*
 * Copyright(c) 2016 - 2026 Puma Security, LLC (https://pumasecurity.io)
 *
 * Project Leads:
 * Eric Johnson (eric.johnson@pumascan.com)
 * Eric Mead (eric.mead@pumascan.com)
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
using Puma.Security.Rules.Analyzer.Validation.Certificate.Core;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Diagnostics;

namespace Puma.Security.Rules.Analyzer.Validation.Certificate
{
    [SupportedDiagnostic(DiagnosticId.SEC0113)]
    internal class CertificateValidationSimpleAssignmentAnalyzer : BaseSemanticAnalyzer, ISyntaxAnalyzer
    {
        private readonly IHttpClientHandlerCertificateValidationExpressionAnalyzer
            _httpClientHandlerCertificateValidationExpression;

        private readonly IWebRequestHandlerCertificateValidationExpressionAnalyzer
            _handlerCertificateValidationExpression;

        private readonly IHttpWebRequestCertificateValidationExpressionAnalyzer
            _requestCertificateValidationExpressionAnalyzer;

        private readonly IServicePointManagerCertificateValidationExpressionAnalyzer
            _servicePointManagerCertificateValidationExpression;

        private readonly IAssignmentExpressionVulnerableSyntaxNodeFactory _vulnerableSyntaxNodeFactory;

        internal CertificateValidationSimpleAssignmentAnalyzer() :
            this(new HttpClientHandlerCertificateValidationExpressionAnalyzer(),
                new WebRequestHandlerCertificateValidationExpressionAnalyzer(),
                new ServicePointManagerCertificateValidationExpressionAnalyzer(),
                new HttpWebRequestCertificateValidationExpressionAnalyzer(),
                new AssignmentExpressionVulnerableSyntaxNodeFactory())
        {
        }

        private CertificateValidationSimpleAssignmentAnalyzer(
            IHttpClientHandlerCertificateValidationExpressionAnalyzer httpClientHandlerCertificateValidationExpression,
            IWebRequestHandlerCertificateValidationExpressionAnalyzer handlerCertificateValidationExpression,
            IServicePointManagerCertificateValidationExpressionAnalyzer servicePointManagerCertificateValidationExpression,
            IHttpWebRequestCertificateValidationExpressionAnalyzer requestCertificateValidationExpressionAnalyzer,
            IAssignmentExpressionVulnerableSyntaxNodeFactory vulnerableSyntaxNodeFactory)
        {
            _httpClientHandlerCertificateValidationExpression = httpClientHandlerCertificateValidationExpression;
            _handlerCertificateValidationExpression = handlerCertificateValidationExpression;
            _servicePointManagerCertificateValidationExpression = servicePointManagerCertificateValidationExpression;
            _requestCertificateValidationExpressionAnalyzer = requestCertificateValidationExpressionAnalyzer;
            _vulnerableSyntaxNodeFactory = vulnerableSyntaxNodeFactory;
        }

        public SyntaxKind SinkKind => SyntaxKind.SimpleAssignmentExpression;

        public override void GetSinks(SyntaxNodeAnalysisContext context, DiagnosticId ruleId)
        {
            var syntax = context.Node as AssignmentExpressionSyntax;

            if (_httpClientHandlerCertificateValidationExpression.IsVulnerable(context.SemanticModel, syntax, ruleId))
                if (VulnerableSyntaxNodes.All(p => p.Sink.GetLocation() != syntax?.GetLocation()))
                    VulnerableSyntaxNodes.Push(_vulnerableSyntaxNodeFactory.Create(syntax));

            if (_handlerCertificateValidationExpression.IsVulnerable(context.SemanticModel, syntax, ruleId))
                if (VulnerableSyntaxNodes.All(p => p.Sink.GetLocation() != syntax?.GetLocation()))
                    VulnerableSyntaxNodes.Push(_vulnerableSyntaxNodeFactory.Create(syntax));

            if (_servicePointManagerCertificateValidationExpression.IsVulnerable(context.SemanticModel, syntax, ruleId))
                if (VulnerableSyntaxNodes.All(p => p.Sink.GetLocation() != syntax?.GetLocation()))
                    VulnerableSyntaxNodes.Push(_vulnerableSyntaxNodeFactory.Create(syntax));

            if (_requestCertificateValidationExpressionAnalyzer.IsVulnerable(context.SemanticModel, syntax, ruleId))
                if (VulnerableSyntaxNodes.All(p => p.Sink.GetLocation() != syntax?.GetLocation()))
                    VulnerableSyntaxNodes.Push(_vulnerableSyntaxNodeFactory.Create(syntax));
        }
    }
}
