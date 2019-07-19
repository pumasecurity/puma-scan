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

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Common;
using Puma.Security.Rules.Common.Extensions;

namespace Puma.Security.Rules.Analyzer.Validation.Csrf.Core
{
    internal class AntiForgeryTokenExpressionAnalyzer : IAntiForgeryTokenExpressionAnalyzer
    {
        private const string _MODIFICATION_VERB_ATTRIBUTES = "HttpDelete|HttpPatch|HttpPost|HttpPut";
        private readonly string[] _ACTION_RESULT_NAMESPACES = new string[] { "System.Web.Mvc.ActionResult", "Microsoft.AspNetCore.Mvc.IActionResult", "Microsoft.AspNetCore.Mvc.ActionResult" };
        private const string _ANTI_FORGERY_TOKEN_ATTRIBUTE = "ValidateAntiForgeryToken";
        private const string _ANONYMOUS_ATTRIBUTE = "AllowAnonymous";

        public bool IsVulnerable(SemanticModel model, MethodDeclarationSyntax syntax)
        {
            //Quick check - public methods only
            if (!syntax.Modifiers.Any(i => i.Kind() == SyntaxKind.PublicKeyword))
                return false;

            //Verify the return type is an expected value.
            if (syntax == null || !syntax.ContainsReturnType(model, _ACTION_RESULT_NAMESPACES))
                return false;

            //Assuming a good design pattern where GET requests (no method decoration) actually
            //only retrieve data and do not make a data modifications. We all know this isn't always the case,
            //but this is to reduce false positives on methods that are not vulnerable
            if (syntax.AttributeLists.Count == 0)
                return false;

            //Search for HttpPost, HttpPut, HttpPatch, and HttpDelete decorators on the action
            var dataModification = false;
            var validateAntiForgeryToken = false;
            var anonymousMethod = false;

            foreach (var attributeSyntax in syntax.AttributeLists)
            {
                foreach (var attribute in attributeSyntax.Attributes)
                {
                    //Check for action verb (post, put, delete, etc.)
                    if (!dataModification && _MODIFICATION_VERB_ATTRIBUTES.Split('|').Contains(attribute.Name?.ToString()))
                        dataModification = true;

                    //Check for anti forgery token method
                    if (!validateAntiForgeryToken && string.Compare(attribute.Name?.ToString(), _ANTI_FORGERY_TOKEN_ATTRIBUTE) == 0)
                        validateAntiForgeryToken = true;

                    //Check for anoynmous attribute (reduces fps)
                    if (!anonymousMethod && string.Compare(attribute.Name?.ToString(), _ANONYMOUS_ATTRIBUTE) == 0)
                        anonymousMethod = true;
                }
            }

            return dataModification && !validateAntiForgeryToken && !anonymousMethod;
        }
    }
}