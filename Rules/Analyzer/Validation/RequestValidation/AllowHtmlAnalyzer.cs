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
using System;

using Puma.Security.Rules.Common;
using Puma.Security.Rules.Diagnostics;
using Puma.Security.Rules.Model;

using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis;

namespace Puma.Security.Rules.Analyzer.Validation.RequestValidation
{
    [SupportedDiagnostic(DiagnosticId.SEC0022)]
    public class AllowHtmlAnalyzer : ISyntaxNodeAnalyzer
    {
        public SyntaxKind Kind => SyntaxKind.PropertyDeclaration;

        public IEnumerable<DiagnosticInfo> GetDiagnosticInfo(SyntaxNodeAnalysisContext context)
        {
            var result = new List<DiagnosticInfo>();
            var property = context.Node as PropertyDeclarationSyntax;

            foreach (AttributeListSyntax attributeList in property.AttributeLists)
            {
                foreach (AttributeSyntax attribute in attributeList.Attributes)
                {
                    //Check attribute name for the AllowHtml keyword
                    if (string.Compare(attribute.Name?.ToString(), "AllowHtml") != 0)
                        continue;

                    //Verify the namespace before adding the diagnostic warning
                    var symbol = context.SemanticModel.GetSymbolInfo(attribute).Symbol as ISymbol;
                    if (string.Compare(symbol?.ContainingNamespace.ToString(), "System.Web.Mvc", StringComparison.Ordinal) == 0)
                    {
                        result.Add(new DiagnosticInfo(attribute.GetLocation()));
                    }
                }
            }

            return result;
        }
    }
}
