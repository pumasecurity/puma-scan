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

using System.Collections.Generic;

using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

using Puma.Security.Rules.Analyzer.Validation.Certificate.Core;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Diagnostics;
using Puma.Security.Rules.Model;

namespace Puma.Security.Rules.Analyzer.Validation.Certificate
{
    [SupportedDiagnostic(DiagnosticId.SEC0113)]
    public class CertificateValidationAnalyzer : ISyntaxNodeAnalyzer
    {
        private readonly IWebRequestHandlerCertificateValidationExpressionAnalyzer
            _handlerCertificateValidationExpression;

        private readonly IHttpWebRequestCertificateValidationExpressionAnalyzer
            _requestCertificateValidationExpressionAnalyzer;

        private readonly IServicePointManagerCertificateValidationExpressionAnalyzer
            _servicePointManagerCertificateValidationExpression;

        public CertificateValidationAnalyzer(
            IWebRequestHandlerCertificateValidationExpressionAnalyzer handlerCertificateValidationExpression,
            IServicePointManagerCertificateValidationExpressionAnalyzer
                servicePointManagerCertificateValidationExpression,
            IHttpWebRequestCertificateValidationExpressionAnalyzer requestCertificateValidationExpressionAnalyzer)
        {
            _handlerCertificateValidationExpression = handlerCertificateValidationExpression;
            _servicePointManagerCertificateValidationExpression = servicePointManagerCertificateValidationExpression;
            _requestCertificateValidationExpressionAnalyzer = requestCertificateValidationExpressionAnalyzer;
        }

        public SyntaxKind Kind => SyntaxKind.AddAssignmentExpression;

        public IEnumerable<DiagnosticInfo> GetDiagnosticInfo(SyntaxNodeAnalysisContext context)
        {
            var result = new List<DiagnosticInfo>();
            var syntax = context.Node as AssignmentExpressionSyntax;

            if (_handlerCertificateValidationExpression.IsVulnerable(context.SemanticModel, syntax))
                result.Add(new DiagnosticInfo(syntax.GetLocation()));

            if (_servicePointManagerCertificateValidationExpression.IsVulnerable(context.SemanticModel, syntax))
                result.Add(new DiagnosticInfo(syntax.GetLocation()));

            if (_requestCertificateValidationExpressionAnalyzer.IsVulnerable(context.SemanticModel, syntax))
                result.Add(new DiagnosticInfo(syntax.GetLocation()));

            return result;
        }
    }
}