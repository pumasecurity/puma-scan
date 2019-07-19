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

namespace Puma.Security.Rules.Analyzer.Configuration.HttpRuntime
{
    [SupportedDiagnostic(DiagnosticId.SEC0009)]
    internal class VersionHeaderAnalyzer : BaseConfigurationFileAnalyzer, IConfigurationFileAnalyzer
    {
        private const string HTTPRUNTIME_SEARCH_EXPRESSION = "configuration/system.web/httpRuntime";

        public void OnCompilationEnd(PumaCompilationAnalysisContext context)
        {
            foreach (var config in ConfigurationFiles)
            {
                //Search for the element in question
                var element = config.ProductionConfigurationDocument.XPathSelectElement(HTTPRUNTIME_SEARCH_EXPRESSION);
                if (element == null)
                    continue;

                //Get the enableVersionHeader attribute
                var attribute = element.Attribute("enableVersionHeader");

                //Default value is true, so it must be set to false
                if (attribute == null || string.Compare(attribute.Value, "false", StringComparison.OrdinalIgnoreCase) != 0)
                {
                    var lineInfo = config.GetProductionLineInfo(element, HTTPRUNTIME_SEARCH_EXPRESSION);
                    VulnerableAdditionalText.Push(new DiagnosticInfo(config.Source.Path, lineInfo.LineNumber, element.ToString()));
                }
            }
        }
    }
}