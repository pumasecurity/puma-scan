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

using System.Collections.Concurrent;
using System.Linq;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

using Puma.Security.Rules.Common;
using Puma.Security.Rules.Core;

namespace Puma.Security.Rules.Analyzer.Core
{
    internal class BaseCodeBlockAnalyzer
    {
        public ConcurrentStack<VulnerableSyntaxNode> VulnerableSyntaxNodes { get; } =
            new ConcurrentStack<VulnerableSyntaxNode>();

        public virtual void GetSinks(SyntaxNodeAnalysisContext context, DiagnosticId ruleId)
        {
        }

        public virtual void OnCompilationEnd(PumaCompilationAnalysisContext pumaContext)
        {
            var context = pumaContext.RosylnContext;

            if (VulnerableSyntaxNodes.IsEmpty)
                return;

            foreach (var vulnerableSyntaxNode in VulnerableSyntaxNodes)
            {
                var canSuppress = false;
                var sources = vulnerableSyntaxNode.Source;
                foreach (var syntaxNode in sources)
                {
                    var idsToMatchOn = syntaxNode.DescendantNodesAndSelf().OfType<IdentifierNameSyntax>();
                    foreach (var identifierNameSyntax in idsToMatchOn)
                    {
                        var containingBlock = syntaxNode.FirstAncestorOrSelf<MethodDeclarationSyntax>();

                        var idMatches = containingBlock
                            .DescendantNodes()
                            .OfType<IdentifierNameSyntax>()
                            .Where(p => p.Identifier.ValueText == syntaxNode.ToString())
                            .ToList<SyntaxNode>();

                        var declarationMatches = containingBlock
                            .DescendantNodes()
                            .OfType<VariableDeclaratorSyntax>()
                            .Where(p => p.Identifier.ValueText == identifierNameSyntax.ToString())
                            .Select(p => p.Initializer.Value)
                            .ToList<SyntaxNode>();

                        var matches = idMatches.Union(declarationMatches);
                        var idModel = context.Compilation.GetSemanticModel(syntaxNode.SyntaxTree);

                        foreach (var match in matches)
                        {
                            var indexNode = match.AncestorsAndSelf().FirstOrDefault();

                            while (!canSuppress && indexNode != containingBlock)
                            {
                                var nodeAnalyzer = SyntaxNodeAnalyzerFactory.Create(indexNode);
                                canSuppress = nodeAnalyzer.CanSuppress(idModel, indexNode, pumaContext.DiagnosticId);

                                indexNode = indexNode.Ancestors().FirstOrDefault();
                            }

                            if (canSuppress)
                            {
                                break;
                            }
                        }

                        if (canSuppress)
                        {
                            break;
                        }
                    }

                    if (canSuppress)
                    {
                        break;
                    }

                }

                vulnerableSyntaxNode.Suppressed = canSuppress;
            }
        }
    }
}