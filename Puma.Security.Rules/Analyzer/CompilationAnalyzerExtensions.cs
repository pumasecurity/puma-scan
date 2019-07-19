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

using System;
using System.Linq;

using Microsoft.CodeAnalysis;

using Puma.Security.Rules.Common;
using Puma.Security.Rules.Diagnostics;

namespace Puma.Security.Rules.Analyzer
{
    internal static class CompilationAnalyzerExtensions
    {
        internal static DiagnosticDescriptor GetDiagnosticDescriptor(this ICompilationAnalyzer analyzer)
        {
            var diagnosticAnalyzerAttribute = analyzer.GetSupportedDiagnosticAttribute();

            return diagnosticAnalyzerAttribute.GetDescriptor();
        }

        internal static SupportedDiagnosticAttribute GetSupportedDiagnosticAttribute(this ICompilationAnalyzer analyzer)
        {
            var supportedDiagnosticAttribute = analyzer.GetType()
                .GetCustomAttributes(typeof(SupportedDiagnosticAttribute), true)
                .FirstOrDefault() as SupportedDiagnosticAttribute;

            return supportedDiagnosticAttribute;
        }

        internal static DiagnosticId GetDiagnosticId(this ICompilationAnalyzer analyzer)
        {
            var diagnosticAnalyzerAttribute = analyzer.GetSupportedDiagnosticAttribute();

            DiagnosticId diagnosticId;
            Enum.TryParse(diagnosticAnalyzerAttribute.Code, out diagnosticId);

            return diagnosticId;
        }
    }
}