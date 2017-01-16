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

using Puma.Security.Rules.Analyzer.Validation.Path.Core;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Diagnostics;
using Puma.Security.Rules.Model;

namespace Puma.Security.Rules.Analyzer.Validation.Path
{
    [SupportedDiagnostic(DiagnosticId.SEC0112)]
    public class IOFileAnalyzer : ISyntaxNodeAnalyzer
    {
        private readonly IFileReadExpressionAnalyzer _fileReadExpressionAnalyzer;
        private readonly IFileWriteExpressionAnalyzer _fileWriteExpressionAnalyzer;
        private readonly IFileOpenExpressionAnalyzer _fileOpenExpressionAnalyzer;
        private readonly IFileDeleteExpressionAnalyzer _fileDeleteExpressionAnalyzer;

        public IOFileAnalyzer(IFileReadExpressionAnalyzer fileReadExpressionAnalyzer, IFileWriteExpressionAnalyzer fileWriteExpressionAnalyzer, IFileOpenExpressionAnalyzer fileOpenExpressionAnalyzer, IFileDeleteExpressionAnalyzer fileDeleteExpressionAnalyzer)
        {
            _fileReadExpressionAnalyzer = fileReadExpressionAnalyzer;
            _fileWriteExpressionAnalyzer = fileWriteExpressionAnalyzer;
            _fileOpenExpressionAnalyzer = fileOpenExpressionAnalyzer;
            _fileDeleteExpressionAnalyzer = fileDeleteExpressionAnalyzer;
        }

        public SyntaxKind Kind => SyntaxKind.InvocationExpression;

        public IEnumerable<DiagnosticInfo> GetDiagnosticInfo(SyntaxNodeAnalysisContext context)
        {
            var result = new List<DiagnosticInfo>();
            var syntax = context.Node as InvocationExpressionSyntax;

            if (_fileReadExpressionAnalyzer.IsVulnerable(context.SemanticModel, syntax))
                result.Add(new DiagnosticInfo(syntax.GetLocation(), "File"));

            if(_fileWriteExpressionAnalyzer.IsVulnerable(context.SemanticModel, syntax))
                result.Add(new DiagnosticInfo(syntax.GetLocation(), "File"));

            if (_fileOpenExpressionAnalyzer.IsVulnerable(context.SemanticModel, syntax))
                result.Add(new DiagnosticInfo(syntax.GetLocation(), "File"));

            if (_fileDeleteExpressionAnalyzer.IsVulnerable(context.SemanticModel, syntax))
                result.Add(new DiagnosticInfo(syntax.GetLocation(), "File"));

            return result;
        }
    }
}
