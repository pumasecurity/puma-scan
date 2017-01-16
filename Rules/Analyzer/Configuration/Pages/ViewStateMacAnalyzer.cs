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

using System;
using System.Collections.Generic;
using System.Threading;
using System.Xml.XPath;

using Puma.Security.Rules.Common;
using Puma.Security.Rules.Common.Extensions;
using Puma.Security.Rules.Diagnostics;
using Puma.Security.Rules.Model;

namespace Puma.Security.Rules.Analyzer.Configuration.Pages
{
    [SupportedDiagnostic(DiagnosticId.SEC0011)]
    public class ViewStateMacAnalyzer : IConfigurationFileAnalyzer
    {
        private const string SEARCH_EXPRESSION = "configuration/system.web/pages";

        public IEnumerable<DiagnosticInfo> GetDiagnosticInfo(IEnumerable<ConfigurationFile> srcFiles,
            CancellationToken cancellationToken)
        {
            var result = new List<DiagnosticInfo>();

            foreach (var config in srcFiles)
            {
                //Search for the element in question
                var element = config.ProductionConfigurationDocument.XPathSelectElement(SEARCH_EXPRESSION);

                //Get the cookieless attribute
                var attribute = element?.Attribute("enableViewStateMac");

                //Default value is true, so it's a non issue
                if (attribute == null)
                    continue;

                //Add waring if present and set to false
                if (string.Compare(attribute.Value, "false", StringComparison.OrdinalIgnoreCase) == 0)
                {
                    var lineInfo = config.GetProductionLineInfo(element, SEARCH_EXPRESSION);
                    result.Add(new DiagnosticInfo(config.Source.Path, lineInfo.LineNumber, element.ToString()));
                }
            }

            return result;
        }
    }
}