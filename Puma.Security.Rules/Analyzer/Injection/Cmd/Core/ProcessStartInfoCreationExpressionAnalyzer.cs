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

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Common;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Puma.Security.Rules.Analyzer.Injection.Cmd.Core
{
    internal class ProcessStartInfoCreationExpressionAnalyzer : IProcessStartInfoCreationExpressionAnalyzer
    {
        public List<SyntaxNode> Sources { get; set; }

        public ProcessStartInfoCreationExpressionAnalyzer()
        {
            Sources = new List<SyntaxNode>();
        }

        public bool IsVulnerable(SemanticModel model, ObjectCreationExpressionSyntax syntax, DiagnosticId ruleId)
        {
            //These persist from previous invocations (clear before staring)
            //TODO: Make this lock during execution until we call ToImmutableArray() after this is done
            this.Sources.Clear();

            //Cheap check for class & method name
            if (!ContainsTypeName(syntax)) return false;

            //If we found it, verify the namespace
            var symbol = model.GetSymbolInfo(syntax).Symbol;
            if (!IsType(symbol)) return false;

            //Bail if no initializers or arguments to analyze
            if (syntax.Initializer?.Expressions.Count == 0 && syntax.ArgumentList?.Arguments.Count == 0)
                return false;

            //Constructor options
            //  0 parms passes onto the assignment expression analyzer
            //  1 param (filename)
            //  2 param (filename, arguments)

            if (syntax.ArgumentList?.Arguments.Count > 0)
            {
                //File name parameter checks
                var fileNameSyntax = syntax.ArgumentList.Arguments[0].Expression;
                var expressionAnalyzer = SyntaxNodeAnalyzerFactory.Create(fileNameSyntax);
                if (!expressionAnalyzer.CanIgnore(model, fileNameSyntax)
                    && !expressionAnalyzer.CanSuppress(model, fileNameSyntax, ruleId))
                {
                    this.Sources.Add(fileNameSyntax);
                }

                //Arguments parameter checks
                if (syntax.ArgumentList?.Arguments.Count > 1)
                {
                    var argumenetSyntax = syntax.ArgumentList.Arguments[1].Expression;
                    expressionAnalyzer = SyntaxNodeAnalyzerFactory.Create(argumenetSyntax);
                    if (!expressionAnalyzer.CanIgnore(model, argumenetSyntax)
                        && !expressionAnalyzer.CanSuppress(model, argumenetSyntax, ruleId))
                    {
                        this.Sources.Add(argumenetSyntax);
                    }
                }
            }

            //Bail if no initializers or arguments to analyze
            if (syntax.Initializer?.Expressions.Count > 0)
            {
                var filter = syntax.Initializer?.Expressions.OfType<AssignmentExpressionSyntax>()
                   .FirstOrDefault(p => (p.Left as IdentifierNameSyntax)?.Identifier.ValueText == "FileName");

                if (filter != null)
                {
                    var expressionAnalyzer = SyntaxNodeAnalyzerFactory.Create(filter.Right);
                    if (!expressionAnalyzer.CanIgnore(model, filter.Right) && !expressionAnalyzer.CanSuppress(model, filter.Right, ruleId))
                    {
                        this.Sources.Add(filter.Right);
                    }
                }

                filter = syntax.Initializer?.Expressions.OfType<AssignmentExpressionSyntax>()
                   .FirstOrDefault(p => (p.Left as IdentifierNameSyntax)?.Identifier.ValueText == "Arguments");

                if (filter != null)
                {
                    var expressionAnalyzer = SyntaxNodeAnalyzerFactory.Create(filter.Right);
                    if (!expressionAnalyzer.CanIgnore(model, filter.Right) && !expressionAnalyzer.CanSuppress(model, filter.Right, ruleId))
                    {
                        this.Sources.Add(filter.Right);
                    }
                }
            }

            return this.Sources != null && this.Sources.Count > 0;
        }

        private static bool ContainsTypeName(ObjectCreationExpressionSyntax syntax)
        {
            return string.Compare(syntax?.Type.ToString(), "ProcessStartInfo", StringComparison.Ordinal) == 0;
        }

        private bool IsType(ISymbol symbol)
        {
            if (symbol == null)
                return false;

            return string.Compare(symbol.ContainingNamespace.ToString(), "System.Diagnostics") == 0;
        }
    }
}