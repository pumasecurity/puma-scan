/* 
 * Copyright(c) 2016 - 2018 Puma Security, LLC (https://www.pumascan.com)
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

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

using Puma.Security.Rules.Analyzer;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Core.ConfigurationFiles;
using Puma.Security.Rules.Filters;
using Puma.Security.Rules.Model;

namespace Puma.Security.Rules.Core
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class BaseConfigurationFileDiagnosticSuite : BaseDiagnosticSuite
    {
        private readonly IFileExtensionFilter _configurationFileFilter;
        private readonly IConfigurationFileParser _configurationFileParser;

        public BaseConfigurationFileDiagnosticSuite()
        {
            _configurationFileFilter = new ConfigurationFileFilter();
            _configurationFileParser = new ConfigurationFileParser();
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

        public override void Initialize(AnalysisContext context)
        {
            base.Initialize(context);

            foreach (var analyzer in Analyzers.OfType<IConfigurationFileAnalyzer>())
            {
                context.RegisterCompilationAction(c =>
                {
                    analyzer.ConfigurationFiles = Parse(c);

                    analyzer.OnCompilationEnd(c);
                    while (!analyzer.VulnerableAdditionalText.IsEmpty)
                    {
                        DiagnosticInfo additionalText;
                        if (!analyzer.VulnerableAdditionalText.TryPop(out additionalText))
                            continue;

                        var supportedDiagnostic = GetSupportedDiagnosticAttribute(analyzer);
                        var diagnostic = DiagnosticFactory.Create(supportedDiagnostic.GetDescriptor(), additionalText);

                        c.ReportDiagnostic(diagnostic);
                    }
                });
            }
        }
    }
}