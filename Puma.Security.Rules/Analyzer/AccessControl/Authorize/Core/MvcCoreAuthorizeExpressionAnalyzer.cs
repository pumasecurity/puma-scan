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

using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Puma.Security.Rules.Common.Extensions;

namespace Puma.Security.Rules.Analyzer.AccessControl.Authorize.Core
{
    internal class MvcCoreAuthorizeExpressionAnalyzer : IAuthorizeExpressionAnalyzer
    {
        protected string[] _CLASS_DECLARATIONS { get; } = new string[] { "Microsoft.AspNetCore.Mvc.Controller", "Microsoft.AspNetCore.Mvc.ControllerBase" };
        protected string[] _AUTHORIZE_SYNATXES { get; } = new string[] { "Microsoft.AspNetCore.Authorization.AuthorizeAttribute" };
        protected string[] _ACTION_RESULT_SYNTAXES { get; } = new string[] { "Microsoft.AspNetCore.Mvc.ActionResult", "Microsoft.AspNetCore.Mvc.IActionResult" };
        protected string[] _ANONYMOUS_ATTRIBUTES { get; } = new string[] { "Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute" };

        public List<SyntaxNode> IsVulnerable(SemanticModel model, ClassDeclarationSyntax syntax)
        {
            List<SyntaxNode> sources = new List<SyntaxNode>();

            //Check the class declaration
            if (!hasBaseClass(model, syntax))
                return sources;

            //Pull the list of candidate methods
            var methodDeclarations = syntax.Members.Where(i => i.Kind() == SyntaxKind.MethodDeclaration).ToList();

            foreach (MemberDeclarationSyntax member in methodDeclarations)
            {
                MethodDeclarationSyntax methodSyntax = member as MethodDeclarationSyntax;
                if (methodSyntax == null)
                    continue;

                //Quick check - public methods only
                if (!methodSyntax.Modifiers.Any(i => i.Kind() == SyntaxKind.PublicKeyword))
                    continue;

                //If does not have the correct return type
                if (!methodSyntax.ContainsReturnType(model, _ACTION_RESULT_SYNTAXES))
                    continue;

                //Check method declaration for attributes
                if (isMissingAuthorizeAttribute(model, methodSyntax.AttributeLists))
                    sources.Add(methodSyntax.ReturnType);
            }

            return sources;
        }

        private bool hasBaseClass(SemanticModel model, ClassDeclarationSyntax syntax)
        {
            var classDeclaration = syntax.GetClassDeclaration();
            if (classDeclaration == null)
                return false;

            var symbol = model.GetDeclaredSymbol(classDeclaration) as INamedTypeSymbol;
            if (symbol == null)
                return false;

            //First check, make sure class is inheriting from a candidate
            if (!symbol.InheritsFrom(_CLASS_DECLARATIONS))
                return false;


            if (!isMissingAuthorizeAttribute(model, classDeclaration.AttributeLists))
                return false;

            return true;
        }

        private bool isMissingAuthorizeAttribute(SemanticModel model, SyntaxList<AttributeListSyntax> attributeList)
        {
            bool hasAnonymous = false;
            bool hasAuthorize = false;

            foreach (var attributeSyntax in attributeList)
            {
                foreach (var attribute in attributeSyntax.Attributes)
                {
                    //Grab the method symbol
                    var symbol = model.GetSymbolInfo(attribute).Symbol as IMethodSymbol;
                    if (symbol == null)
                        continue;

                    //Get containing type
                    var containingType = symbol.ContainingType;
                    if (containingType == null)
                        continue;

                    //Check for existence of the anonymous attribute
                    if (!hasAnonymous)
                    {
                        hasAnonymous = containingType.InheritsFrom(_ANONYMOUS_ATTRIBUTES);
                    }

                    //Check for the existence of the authorize attribute
                    if (!hasAuthorize)
                    {
                        hasAuthorize = containingType.InheritsFrom(_AUTHORIZE_SYNATXES);
                    }
                }
            }

            //If missing both, we have a candidate
            return !hasAuthorize && !hasAnonymous;
        }
    }
}
