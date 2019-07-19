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

namespace Puma.Security.Rules.Analyzer.Configuration.CustomErrors
{
    [SupportedDiagnostic(DiagnosticId.SEC0002)]
    internal class CustomErrorsAnalyzer : BaseConfigurationFileAnalyzer, IConfigurationFileAnalyzer
    {
        private const string CUSTOMERRORS_SEARCH_EXPRESSION = "configuration/system.web/customErrors";

        public void OnCompilationEnd(PumaCompilationAnalysisContext context)
        {
            foreach (var config in ConfigurationFiles)
            {
                var customErrors =
                    config.ProductionConfigurationDocument.XPathSelectElement(CUSTOMERRORS_SEARCH_EXPRESSION);

                //Default (<customErrors mode="RemoteOnly" />) is not an issue
                //Look for the mode attribute, again default val is not an issue
                var mode = customErrors?.Attribute("mode");
                if (mode == null)
                    continue;

                //Any value that is not "Off" is ok
                if (string.Compare(mode.Value, "Off", StringComparison.OrdinalIgnoreCase) != 0)
                    continue;

                var lineInfo = config.GetProductionLineInfo(customErrors, CUSTOMERRORS_SEARCH_EXPRESSION);
                VulnerableAdditionalText.Push(new DiagnosticInfo(config.Source.Path, lineInfo.LineNumber, customErrors.ToString()));
            }
        }
    }
}