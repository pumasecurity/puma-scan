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
using System.Collections.Generic;
using System.Linq;

using Microsoft.CodeAnalysis.Diagnostics;

using Puma.Security.Rules.Analyzer;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Core.ConfigurationFiles;
using Puma.Security.Rules.Diagnostics;
using Puma.Security.Rules.Filters;
using Puma.Security.Rules.Model;

namespace Puma.Security.Rules.Core
{
    internal class ConfigurationFileAnalyzerRegisterService : IConfigurationFileAnalyzerRegisterService
    {
        private readonly IConfigurationFileParser _configurationFileParser;
        private readonly IFileExtensionFilter _configurationFileFilter;
        private readonly IDiagnosticFactory _diagnosticFactory;

        internal ConfigurationFileAnalyzerRegisterService() : this(new ConfigurationFileParser(), new ConfigurationFileFilter(), new DiagnosticFactory())
        {
            
        }

        private ConfigurationFileAnalyzerRegisterService(IConfigurationFileParser configurationFileParser, IFileExtensionFilter configurationFileFilter, IDiagnosticFactory diagnosticFactory)
        {
            _configurationFileParser = configurationFileParser;
            _configurationFileFilter = configurationFileFilter;
            _diagnosticFactory = diagnosticFactory;
        }
      

        public void Register(AnalysisContext context, ICompilationAnalyzer analyzer)
        {
            var configurationFileAnalyzer = analyzer as IConfigurationFileAnalyzer;
            if (configurationFileAnalyzer == null)
                return;

            context.RegisterCompilationAction(c =>
            {
                configurationFileAnalyzer.ConfigurationFiles = Parse(c);

                var pumaContext = new PumaCompilationAnalysisContext(configurationFileAnalyzer.GetDiagnosticId(), c);

                configurationFileAnalyzer.OnCompilationEnd(pumaContext);
                while (!configurationFileAnalyzer.VulnerableAdditionalText.IsEmpty)
                {
                    DiagnosticInfo additionalText;
                    if (!configurationFileAnalyzer.VulnerableAdditionalText.TryPop(out additionalText))
                        continue;

                    var supportedDiagnostic = configurationFileAnalyzer.GetSupportedDiagnosticAttribute();

                    var diagnostic = _diagnosticFactory.Create(supportedDiagnostic.GetDescriptor(), additionalText);

                    c.ReportDiagnostic(diagnostic);
                }
            });
        }

        private IEnumerable<ConfigurationFile> Parse(CompilationAnalysisContext context)
        {
            if (!context.Options.AdditionalFiles.Any())
                return new List<ConfigurationFile>();

            var srcFiles = _configurationFileFilter.GetFiles(context.Options.AdditionalFiles).ToList();

            if (!srcFiles.Any())
                return new List<ConfigurationFile>();

            var workingDirectory = Utils.GetWorkingDirectory(context.Compilation.AssemblyName);
            var basePath = Utils.GetCommonRootPath(srcFiles);

            return srcFiles.Select(src => _configurationFileParser.Parse(src, basePath, workingDirectory)).ToList();
        }
    }
}