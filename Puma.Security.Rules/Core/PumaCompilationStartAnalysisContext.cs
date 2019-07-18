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

using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

using Puma.Security.Rules.Common;

namespace Puma.Security.Rules.Core
{
    internal class PumaCompilationStartAnalysisContext
    {
        private readonly CompilationStartAnalysisContext _context;

        internal PumaCompilationStartAnalysisContext(CompilationStartAnalysisContext context)
        {
            this._context = context;
        }

        internal void RegisterSyntaxNodeAction(Action<PumaSyntaxNodeAnalysisContext> registerSyntaxAction, SyntaxKind syntaxKind, DiagnosticId diagnosticId)
        {
            _context.RegisterSyntaxNodeAction(c =>
            {
                var pumaCompilationEndContext = new PumaSyntaxNodeAnalysisContext(diagnosticId, c);
                registerSyntaxAction.Invoke(pumaCompilationEndContext);
            }, syntaxKind);
        }

        internal void RegisterCompilationEndAction(Action<PumaCompilationAnalysisContext> compilationEndAction, DiagnosticId diagnosticId)
        {
            _context.RegisterCompilationEndAction(c =>
            {
                var pumaCompilationEndContext = new PumaCompilationAnalysisContext(diagnosticId, c);
                compilationEndAction.Invoke(pumaCompilationEndContext);
            });
        }
    }
}