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

using Puma.Security.Rules.Common;
using Puma.Security.Rules.Diagnostics;
using Puma.Security.Rules.Model;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Puma.Security.Rules.Analyzer.Validation.Csrf
{
    [SupportedDiagnostic(DiagnosticId.SEC0019)]
    public class AntiForgeryTokenAnalyzer : ISyntaxNodeAnalyzer
    {
        private const string _MODIFICATION_VERB_ATTRIBUTES = "HttpDelete|HttpPatch|HttpPost|HttpPut";
        private const string _ACTION_RESULT_NAMESPACE = "System.Web.Mvc.ActionResult";
        private const string _ANTI_FORGERY_TOKEN_ATTRIBUTE = "ValidateAntiForgeryToken";

        public SyntaxKind Kind => SyntaxKind.MethodDeclaration;

        public IEnumerable<DiagnosticInfo> GetDiagnosticInfo(SyntaxNodeAnalysisContext context)
        {
            var result = new List<DiagnosticInfo>();

            var method = context.Node as MethodDeclarationSyntax;

            //Grab the method's return type. 2 cases:
            // - GenericNameSyntax (Task<ActionResult>)
            // - IdentifierNameSyntax (ActionResult)
            IdentifierNameSyntax returnType = null;
            if (method?.ReturnType is GenericNameSyntax)
            {
                GenericNameSyntax generic = method?.ReturnType as GenericNameSyntax;
                if (generic.TypeArgumentList.Arguments.Count > 0)
                    returnType = generic.TypeArgumentList.Arguments[0] as IdentifierNameSyntax;
            }
            else
            {
                returnType = method?.ReturnType as IdentifierNameSyntax;
            }

            //If returnType is null, bail out
            if (returnType == null)
                return result;

            //Grab the return type symbol and return if it is not a named type
            var symbol = context.SemanticModel.GetSymbolInfo(returnType).Symbol as INamedTypeSymbol;
            if (symbol == null)
                return result;

            //This could be expensive, but we need search to the base type and determine if this return type
            //inherits from the System.Web.Mvc.ActionResult and verify if the return type is of type ActionResult
            if (!Utils.SymbolInheritsFrom(symbol, _ACTION_RESULT_NAMESPACE))
                return result;

            //Assuming a good design pattern where GET requests (no method decoration) actually
            //only retrieve data and do not make a data modifications. We all know this isn't always the case,
            //but this is to reduce false positives on methods that are not vulnerable
            if (method.AttributeLists.Count == 0)
                return result;

            //Search for HttpPost, HttpPut, HttpPatch, and HttpDelete decorators on the action
            bool dataModification = false;
            bool validateAntiForgeryToken = false;

            foreach(AttributeListSyntax attribute in method.AttributeLists)
            {
                foreach(AttributeSyntax syntax in attribute.Attributes)
                {
                    if(!dataModification && _MODIFICATION_VERB_ATTRIBUTES.Split('|').Contains(syntax.Name?.ToString()))
                        dataModification = true;

                    if (!validateAntiForgeryToken && string.Compare(syntax.Name?.ToString(), _ANTI_FORGERY_TOKEN_ATTRIBUTE) == 0)
                        validateAntiForgeryToken = true;
                }
            }

            if (dataModification && !validateAntiForgeryToken)
                result.Add(new DiagnosticInfo(returnType.GetLocation()));

            return result;
        }
    }
}
