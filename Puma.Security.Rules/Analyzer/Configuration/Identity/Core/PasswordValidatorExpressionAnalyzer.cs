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

using System;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;


namespace Puma.Security.Rules.Analyzer.Configuration.Identity.Core
{
    internal class PasswordValidatorExpressionAnalyzer : IPasswordValidatorExpressionAnalyzer
    {
        public bool IsVulnerable(SemanticModel model, ObjectCreationExpressionSyntax syntax)
        {
            //Check for the type
            if (!ContainsTypeName(syntax)) return false;

            //If we found it, verify the namespace
            var symbol = model.GetSymbolInfo(syntax).Symbol;
            if (!IsType(symbol)) return false;

            //Pull the initialization expressions
            var initializer = syntax.Initializer;

            return isValidPasswordComplexity(model, initializer);
        }

        private static bool ContainsTypeName(ObjectCreationExpressionSyntax syntax)
        {
            return string.Compare(syntax?.Type.ToString(), "PasswordValidator", StringComparison.Ordinal) == 0;
        }

        private bool IsType(ISymbol symbol)
        {
            if (symbol == null)
                return false;

            return string.Compare(symbol.ContainingNamespace.ToString(), "Microsoft.AspNet.Identity") == 0;
        }


        private bool isValidPasswordComplexity(SemanticModel model, InitializerExpressionSyntax syntax)
        {
            if (syntax == null || syntax.Expressions.Count == 0)
                return false;

            //Accouting for the inline assignment expression
            int minLength = 0;
            bool requireSpecialCharacter = false;
            bool requireNumber = false;
            bool requireUpperChar = false;
            bool requireLowerChar = false;

            foreach (AssignmentExpressionSyntax expression in syntax.Expressions)
            {
                //Get the property value
                var value = model.GetConstantValue(expression.Right);

                //If we have a value, set them to the local var
                if (value.HasValue)
                    switch (expression.Left.ToString())
                    {
                        case "RequiredLength":
                            minLength = (int)value.Value;
                            break;
                        case "RequireNonLetterOrDigit":
                            requireSpecialCharacter = (bool)value.Value;
                            break;
                        case "RequireDigit":
                            requireNumber = (bool)value.Value;
                            break;
                        case "RequireLowercase":
                            requireLowerChar = (bool)value.Value;
                            break;
                        case "RequireUppercase":
                            requireUpperChar = (bool)value.Value;
                            break;
                        default:
                            break;
                    }
            }

            return !isValidPasswordComplexity(minLength, requireSpecialCharacter, requireNumber, requireUpperChar, requireLowerChar);
        }

        private bool isValidPasswordComplexity(int minLength, bool specialCharacter, bool digit, bool upper, bool lower)
        {
            if (minLength < RuleOptions.PasswordComplexityMinPasswordLength)
                return false;

            if (RuleOptions.PasswordComplexityRequireNumber && !digit)
                return false;

            if (RuleOptions.PasswordComplexityRequireLowerCharacter && !lower)
                return false;

            if (RuleOptions.PasswordComplexityRequireUpperCharacter && !upper)
                return false;

            if (RuleOptions.PasswordComplexityRequireSpecialCharcter && !specialCharacter)
                return false;

            return true;
        }
    }
}