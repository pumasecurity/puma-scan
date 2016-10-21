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

using System;
using System.IO;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Xml;
using System.Xml.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.Diagnostics;
using System.Xml.Xsl;
using System.Configuration;
using System.Xml.XPath;
using Puma.Security.Rules.Model;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Common.Extensions;
using Puma.Security.Rules.Diagnostics;

namespace Puma.Security.Rules.Analyzer.Configuration
{
    [SupportedDiagnostic(DiagnosticId.SEC0002)]
    public class CustomErrorsAnalyzer : IConfigurationFileAnalyzer
    {
        private const string CUSTOMERRORS_SEARCH_EXPRESSION = "configuration/system.web/customErrors";

        public IEnumerable<DiagnosticInfo> GetDiagnosticInfo(IEnumerable<ConfigurationFile> srcFiles,
            CancellationToken cancellationToken)
        {
            var result = new List<DiagnosticInfo>();

            foreach (var config in srcFiles)
            {
                var customErrors =
                    config.ProductionConfigurationDocument.XPathSelectElement(CUSTOMERRORS_SEARCH_EXPRESSION);

                //Default (<customErrors mode="RemoteOnly" />) is not an issue
                //Look for the mode attribute, again default val is not an issue
                XAttribute mode = customErrors?.Attribute("mode");
                if (mode == null)
                    continue;

                //Any value that is not "Off" is ok
                if (string.Compare(mode.Value, "Off", StringComparison.OrdinalIgnoreCase) != 0)
                    continue;

                var lineInfo = config.GetProductionLineInfo(customErrors, CUSTOMERRORS_SEARCH_EXPRESSION);
                result.Add(new DiagnosticInfo(config.Source.Path, lineInfo.LineNumber, customErrors.ToString()));
            }

            return result;
        }
    }
}