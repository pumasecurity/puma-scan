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
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Puma.Security.Rules.Analyzer.Configuration.Identity
{
    [SupportedDiagnostic(DiagnosticId.SEC0017)]
    public class PasswordComplexityAnalyzer : ISyntaxNodeAnalyzer
    {
        public SyntaxKind Kind => SyntaxKind.ObjectCreationExpression;

        public IEnumerable<DiagnosticInfo> GetDiagnosticInfo(SyntaxNodeAnalysisContext context)
        {
            var result = new List<DiagnosticInfo>();

            var statement = context.Node as ObjectCreationExpressionSyntax;

            if (string.Compare(statement?.Type.ToString(), "PasswordValidator", StringComparison.Ordinal) != 0)
                return result;

            var symbol = context.SemanticModel.GetSymbolInfo(statement).Symbol as ISymbol;
            if (string.Compare(symbol?.ContainingNamespace.ToString(), "Microsoft.AspNet.Identity", StringComparison.Ordinal) != 0)
                return result;

            var initializer = statement.Initializer as InitializerExpressionSyntax;
            if (initializer == null || initializer.Expressions.Count == 0)
                return result;

            //Accouting for the inline assignment expression
            int minLength = 0;
            bool requireSpecialCharacter = false;
            bool requireNumber = false;
            bool requireUpperChar = false;
            bool requireLowerChar = false;

            foreach (AssignmentExpressionSyntax expression in initializer.Expressions)
            {
                //Get the property value
                var value = context.SemanticModel.GetConstantValue(expression.Right);

                //If we have a value, set them to the local var
                if (value.HasValue)
                {
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
            }

            if (!isValidPasswordComplexity(minLength, requireSpecialCharacter, requireNumber, requireUpperChar, requireLowerChar))
            {
                result.Add(new DiagnosticInfo(statement.GetLocation()
                    , RuleOptions.PasswordComplexityMinPasswordLength
                    , RuleOptions.PasswordComplexityRequireNumber, RuleOptions.PasswordComplexityRequireLowerCharacter
                    , RuleOptions.PasswordComplexityRequireUpperCharacter, RuleOptions.PasswordComplexityRequireSpecialCharcter));
            }

            return result;
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
