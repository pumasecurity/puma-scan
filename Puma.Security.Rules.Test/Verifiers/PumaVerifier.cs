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

using System.Threading.Tasks;

using Microsoft.CodeAnalysis.CSharp.Testing;
using Microsoft.CodeAnalysis.Testing;

using Puma.Security.Rules.Suites;

namespace Puma.Security.Rules.Test.Verifiers
{
    /// <summary>
    /// Runs the full PumaDiagnosticSuite over a C# source snippet and verifies
    /// the expected diagnostics (and no others) are reported.
    /// </summary>
    internal static class PumaVerifier
    {
        public static Task VerifyAnalyzerAsync(string source, params DiagnosticResult[] expected)
        {
            var test = new CSharpAnalyzerTest<PumaDiagnosticSuite, DefaultVerifier>
            {
                TestCode = source,
                // The suite registers some rule IDs (e.g. SEC0107, SEC0113) through
                // multiple sink analyzers, so duplicate descriptors are expected.
                MarkupOptions = MarkupOptions.UseFirstDescriptor,
                // The suite analyzes generated code (it never opts out via
                // ConfigureGeneratedCodeAnalysis), so skip the framework's
                // generated-code exclusion check.
                TestBehaviors = TestBehaviors.SkipGeneratedCodeCheck,
            };

            test.ExpectedDiagnostics.AddRange(expected);
            return test.RunAsync();
        }

        public static DiagnosticResult Diagnostic(string diagnosticId)
        {
            return AnalyzerVerifier<PumaDiagnosticSuite, CSharpAnalyzerTest<PumaDiagnosticSuite, DefaultVerifier>, DefaultVerifier>
                .Diagnostic(diagnosticId);
        }
    }
}
