/* 
 * Copyright(c) 2016 Puma Security, LLC (https://www.pumascan.com)
 * 
 * Project Leader: Eric Johnson (eric.johnson@pumascan.com)
 * Lead Developer: Eric Mead (eric.mead@pumascan.com)
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

using Puma.Security.Rules.Common;
using Puma.Security.Rules.Model;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;

using Puma.Security.Rules.Common.Extensions;
using Puma.Security.Rules.Diagnostics;

namespace Puma.Security.Rules.Analyzer.Configuration
{
    [SupportedDiagnostic(DiagnosticId.SEC0016)]
    public class MachineKeyAnalyzer : IConfigurationFileAnalyzer
    {
        private const string SEARCH_EXPRESSION = "configuration/system.web/machineKey";

        public IEnumerable<DiagnosticInfo> GetDiagnosticInfo(IEnumerable<ConfigurationFile> srcFiles,
            CancellationToken cancellationToken)
        {
            var result = new List<DiagnosticInfo>();

            foreach (var config in srcFiles)
            {
                //Search for the element in question
                XElement element = config.ProductionConfigurationDocument.XPathSelectElement(SEARCH_EXPRESSION);
                if (element == null)
                    continue;

                XAttribute attribute = element.Attribute("validationKey");
                bool flag = (attribute != null && !attribute.Value.Contains("AutoGenerate"));

                //Check the decryptionKey element for "AutoGenerate"
                if (!flag)
                {
                    attribute = element.Attribute("decryptionKey");
                    flag = (attribute != null && !attribute.Value.Contains("AutoGenerate"));
                }

                //Send the diagnostic warning if identified cleartext key
                if (flag)
                {
                    var lineInfo = config.GetProductionLineInfo(element, SEARCH_EXPRESSION);
                    result.Add(new DiagnosticInfo(config.Source.Path, lineInfo.LineNumber, element.ToString()));
                }
            }

            return result;
        }
    }
}
