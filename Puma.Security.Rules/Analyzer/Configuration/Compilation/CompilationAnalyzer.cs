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
using System.Xml.XPath;

using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Common.Extensions;
using Puma.Security.Rules.Core;
using Puma.Security.Rules.Diagnostics;
using Puma.Security.Rules.Model;

namespace Puma.Security.Rules.Analyzer.Configuration.Compilation
{
    [SupportedDiagnostic(DiagnosticId.SEC0001)]
    internal class CompilationAnalyzer : BaseConfigurationFileAnalyzer, IConfigurationFileAnalyzer
    {
        private const string COMPILATION_SEARCH_EXPRESSION = "configuration/system.web/compilation";

        public void OnCompilationEnd(PumaCompilationAnalysisContext context)
        {
            foreach (var config in ConfigurationFiles)
            {
                var compilation =
                    config.ProductionConfigurationDocument.XPathSelectElement(COMPILATION_SEARCH_EXPRESSION);

                //Looking for debug set to true
                //Default is false, so it's OK if the element is missing
                var mode = compilation?.Attribute("debug");
                if (mode == null)
                    continue;

                if (string.Compare(mode.Value, "true", StringComparison.OrdinalIgnoreCase) != 0) continue;

                var lineInfo = config.GetProductionLineInfo(compilation, COMPILATION_SEARCH_EXPRESSION);
                VulnerableAdditionalText.Push(new DiagnosticInfo(config.Source.Path, lineInfo.LineNumber, compilation.ToString()));
            }
        }
    }
}