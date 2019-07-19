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

using Puma.Security.Rules.Analyzer.Core;

using Puma.Security.Rules.Analyzer.Core.Factories;
using Puma.Security.Rules.Analyzer.Validation.Path.Core;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Diagnostics;

namespace Puma.Security.Rules.Analyzer.Validation.Path
{
    [SupportedDiagnostic(DiagnosticId.SEC0116)]
    internal class IOFileAnalyzer : BaseCodeBlockAnalyzer, ISyntaxAnalyzer
    {
        private readonly IFileDeleteExpressionAnalyzer _fileDeleteExpressionAnalyzer;
        private readonly IFileOpenExpressionAnalyzer _fileOpenExpressionAnalyzer;
        private readonly IFileReadExpressionAnalyzer _fileReadExpressionAnalyzer;
        private readonly IFileWriteExpressionAnalyzer _fileWriteExpressionAnalyzer;
        private readonly IInvocationExpressionVulnerableSyntaxNodeFactory _vulnerableSyntaxNodeFactory;

        internal IOFileAnalyzer() : this(new FileReadExpressionAnalyzer(), new FileWriteExpressionAnalyzer(), new FileOpenExpressionAnalyzer(), new FileDeleteExpressionAnalyzer(), new InvocationExpressionVulnerableSyntaxNodeFactory()) { }

        private IOFileAnalyzer(
            IFileReadExpressionAnalyzer fileReadExpressionAnalyzer,
            IFileWriteExpressionAnalyzer fileWriteExpressionAnalyzer,
            IFileOpenExpressionAnalyzer fileOpenExpressionAnalyzer,
            IFileDeleteExpressionAnalyzer fileDeleteExpressionAnalyzer,
            IInvocationExpressionVulnerableSyntaxNodeFactory vulnerableSyntaxNodeFactory)
            
        {
            _fileReadExpressionAnalyzer = fileReadExpressionAnalyzer;
            _fileWriteExpressionAnalyzer = fileWriteExpressionAnalyzer;
            _fileOpenExpressionAnalyzer = fileOpenExpressionAnalyzer;
            _fileDeleteExpressionAnalyzer = fileDeleteExpressionAnalyzer;
            _vulnerableSyntaxNodeFactory = vulnerableSyntaxNodeFactory;
        }

        public SyntaxKind SinkKind => SyntaxKind.InvocationExpression;

        public override void GetSinks(SyntaxNodeAnalysisContext context, DiagnosticId ruleId)
        {
            var syntax = context.Node as InvocationExpressionSyntax;

            if (_fileReadExpressionAnalyzer.IsVulnerable(context.SemanticModel, syntax, ruleId))
                if (VulnerableSyntaxNodes.All(p => p.Sink.GetLocation() != syntax?.GetLocation()))
                    VulnerableSyntaxNodes.Push(_vulnerableSyntaxNodeFactory.Create(syntax, "file read"));

            if (_fileWriteExpressionAnalyzer.IsVulnerable(context.SemanticModel, syntax, ruleId))
                if (VulnerableSyntaxNodes.All(p => p.Sink.GetLocation() != syntax?.GetLocation()))
                    VulnerableSyntaxNodes.Push(_vulnerableSyntaxNodeFactory.Create(syntax, "file write"));

            if (_fileOpenExpressionAnalyzer.IsVulnerable(context.SemanticModel, syntax, ruleId))
                if (VulnerableSyntaxNodes.All(p => p.Sink.GetLocation() != syntax?.GetLocation()))
                    VulnerableSyntaxNodes.Push(_vulnerableSyntaxNodeFactory.Create(syntax, "file open"));

            if (_fileDeleteExpressionAnalyzer.IsVulnerable(context.SemanticModel, syntax, ruleId))
                if (VulnerableSyntaxNodes.All(p => p.Sink.GetLocation() != syntax?.GetLocation()))
                    VulnerableSyntaxNodes.Push(_vulnerableSyntaxNodeFactory.Create(syntax, "file delete"));
        }
    }
}