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

using Puma.Security.Rules.Common;

using Microsoft.CodeAnalysis;
using Puma.Security.Rules.Configuration.Core;
using System;

namespace Puma.Security.Rules.Diagnostics
{
    public static class DiagnosticDescriptorFactory
    {
        public static DiagnosticDescriptor Create(string code, DiagnosticSeverity severity = DiagnosticSeverity.Warning, DiagnosticCategory category = DiagnosticCategory.Security)
        {
            LocalizableString title = new LocalizableResourceString(string.Format("Analyzer_{0}_Title", code), Resources.ResourceManager, typeof(Resources));
            LocalizableString description = new LocalizableResourceString(string.Format("Analyzer_{0}_Description", code), Resources.ResourceManager, typeof(Resources));
            LocalizableString message = new LocalizableResourceString(string.Format("Analyzer_{0}_MessageFormat", code), Resources.ResourceManager, typeof(Resources));
            LocalizableString anchor = new LocalizableResourceString(string.Format("Analyzer_{0}_Anchor", code), Resources.ResourceManager, typeof(Resources));

            return new DiagnosticDescriptor(
                code
                , title
                , message
                , getCategoryResource(category)
                , severity
                , true
                , description
                , string.Format("https://www.pumascan.com/rules/#{0}", anchor));
        }

        private static string getCategoryResource(DiagnosticCategory cateogry)
        {
            if (cateogry == DiagnosticCategory.Security)
                return Resources.Analyzer_Category_Security;
            else if (cateogry == DiagnosticCategory.Syntax)
                return Resources.Analyzer_Category_Syntax;
            else
                return Resources.Analyzer_Category_None;
        }
    }
}