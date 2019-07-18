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

using System.Collections.Concurrent;
using System.Linq;
using System.Text.RegularExpressions;

using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Common;
using Puma.Security.Rules.Core;
using Puma.Security.Rules.Diagnostics;
using Puma.Security.Rules.Filters;
using Puma.Security.Rules.Model;
using Puma.Security.Rules.Regex;
using Puma.Security.Rules.Regex.Mvc;

namespace Puma.Security.Rules.Analyzer.Injection.Xss
{
    [SupportedDiagnostic(DiagnosticId.SEC0102)]
    internal class HtmlRawAnalyzer : BaseMarkupFileAnalyzer, IAdditionalTextAnalyzer
    {
        private readonly IRegexHelper _htmlRawRegexHelper;
        private readonly IFileExtensionFilter _mvcMarkupFileFilter;

        internal HtmlRawAnalyzer() : this(new HtmlRawRegexHelper(), new MvcMarkupFileFilter()) { }
        
        private HtmlRawAnalyzer(IRegexHelper htmlRawRegexHelper, IFileExtensionFilter mvcMarkupFileFilter)
        {
            _htmlRawRegexHelper = htmlRawRegexHelper;
            _mvcMarkupFileFilter = mvcMarkupFileFilter;
        }

        public ConcurrentStack<DiagnosticInfo> VulnerableAdditionalText { get; } = new ConcurrentStack<DiagnosticInfo>();

        public void OnCompilationEnd(PumaCompilationAnalysisContext pumaContext)
        {
            var context = pumaContext.RosylnContext;
            if (!context.Options.AdditionalFiles.Any())
                return;

            var srcFiles = _mvcMarkupFileFilter.GetFiles(context.Options.AdditionalFiles).ToList();

            if (!srcFiles.Any())
                return;

            foreach (var file in srcFiles)
            {
                var document = file.GetText();

                var source = document.ToString();

                if (!_htmlRawRegexHelper.HasMatch(source)) continue;

                foreach (Match match in _htmlRawRegexHelper.GetMatches(source))
                    VulnerableAdditionalText.Push(new DiagnosticInfo(file.Path, document.Lines.GetLinePosition(match.Index).Line,
                        source.Substring(match.Index, match.Length)));
            }
        }
    }
}