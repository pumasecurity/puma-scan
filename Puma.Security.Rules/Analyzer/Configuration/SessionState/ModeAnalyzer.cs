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

namespace Puma.Security.Rules.Analyzer.Configuration.SessionState
{
    [SupportedDiagnostic(DiagnosticId.SEC0021)]
    internal class ModeAnalyzer : BaseConfigurationFileAnalyzer, IConfigurationFileAnalyzer
    {
        private const string SEARCH_EXPRESSION = "configuration/system.web/sessionState";

        public void OnCompilationEnd(PumaCompilationAnalysisContext pumaContext)
        {
            foreach (var config in ConfigurationFiles)
            {
                //Search for the element in question
                var element = config.ProductionConfigurationDocument.XPathSelectElement(SEARCH_EXPRESSION);
                if (element == null)
                    continue;

                //Get the timeout attribute value
                var attribute = element.Attribute("mode");
                var mode = attribute?.Value;

                if (string.Compare(mode, "StateServer", StringComparison.Ordinal) == 0)
                {
                    var lineInfo = config.GetProductionLineInfo(element, SEARCH_EXPRESSION);
                    VulnerableAdditionalText.Push(new DiagnosticInfo(config.Source.Path, lineInfo.LineNumber, element.ToString()));
                }
            }
        }
    }
}