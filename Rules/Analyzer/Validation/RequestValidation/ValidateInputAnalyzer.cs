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

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

using Puma.Security.Rules.Common;
using Puma.Security.Rules.Diagnostics;
using Puma.Security.Rules.Model;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Puma.Security.Rules.Analyzer.Validation.RequestValidation
{
    [SupportedDiagnostic(DiagnosticId.SEC0023)]
    public class ValidateInputAnalyzer : ISyntaxNodeAnalyzer
    {
        public SyntaxKind Kind => SyntaxKind.MethodDeclaration;

        public IEnumerable<DiagnosticInfo> GetDiagnosticInfo(SyntaxNodeAnalysisContext context)
        {
            var result = new List<DiagnosticInfo>();
            var method = context.Node as MethodDeclarationSyntax;

            foreach (AttributeListSyntax attributeList in method.AttributeLists)
            {
                foreach (AttributeSyntax attribute in attributeList.Attributes)
                {
                    if (string.Compare(attribute.Name?.ToString(), "ValidateInput") != 0)
                        continue;

                    //Verify the namespace before proceeding
                    var symbol = context.SemanticModel.GetSymbolInfo(attribute).Symbol as ISymbol;
                    if (string.Compare(symbol?.ContainingNamespace.ToString(), "System.Web.Mvc", StringComparison.Ordinal) != 0)
                        continue;

                    AttributeArgumentListSyntax argumentList = attribute.ArgumentList;
                    AttributeArgumentSyntax argument = argumentList.Arguments.First();
                    var value = context.SemanticModel.GetConstantValue(argument?.Expression);

                    if(value.HasValue && (bool)value.Value == false)
                        result.Add(new DiagnosticInfo(attribute.GetLocation()));
                }
            }

            return result;
        }
    }
}
