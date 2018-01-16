/* 
 * Copyright(c) 2016 - 2018 Puma Security, LLC (https://www.pumascan.com)
 * 
 * Project Leader: Eric Johnson (eric.johnson@pumascan.com)
 * Lead Developer: Eric Mead (eric.mead@pumascan.com)
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

using System.Linq;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Common;

namespace Puma.Security.Rules.Analyzer.Validation.Csrf.Core
{
    internal class AntiForgeryTokenExpressionAnalyzer : IAntiForgeryTokenExpressionAnalyzer
    {
        private const string _MODIFICATION_VERB_ATTRIBUTES = "HttpDelete|HttpPatch|HttpPost|HttpPut";
        private const string _ACTION_RESULT_NAMESPACE = "System.Web.Mvc.ActionResult";
        private const string _ANTI_FORGERY_TOKEN_ATTRIBUTE = "ValidateAntiForgeryToken";

        public bool IsVulnerable(SemanticModel model, MethodDeclarationSyntax syntax, IdentifierNameSyntax returnType)
        {
            if (returnType == null)
                return false;

            //Grab the return type symbol and return if it is not a named type
            var symbol = model.GetSymbolInfo(returnType).Symbol as INamedTypeSymbol;
            if (symbol == null)
                return false;

            //This could be expensive, but we need search to the base type and determine if this return type
            //inherits from the System.Web.Mvc.ActionResult and verify if the return type is of type ActionResult
            if (!Utils.SymbolInheritsFrom(symbol, _ACTION_RESULT_NAMESPACE))
                return false;

            //Assuming a good design pattern where GET requests (no method decoration) actually
            //only retrieve data and do not make a data modifications. We all know this isn't always the case,
            //but this is to reduce false positives on methods that are not vulnerable
            if (syntax.AttributeLists.Count == 0)
                return false;

            //Search for HttpPost, HttpPut, HttpPatch, and HttpDelete decorators on the action
            var dataModification = false;
            var validateAntiForgeryToken = false;

            foreach (var attributeSyntax in syntax.AttributeLists)
            foreach (var attribute in attributeSyntax.Attributes)
            {
                if (!dataModification && _MODIFICATION_VERB_ATTRIBUTES.Split('|').Contains(attribute.Name?.ToString()))
                    dataModification = true;

                if (!validateAntiForgeryToken && string.Compare(attribute.Name?.ToString(), _ANTI_FORGERY_TOKEN_ATTRIBUTE) == 0)
                    validateAntiForgeryToken = true;
            }

            return dataModification && !validateAntiForgeryToken;
        }
    }
}