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
using System.Collections.Generic;

using Puma.Security.Rules.Model;

namespace Puma.Security.Rules.Analyzer.Core
{
    internal abstract class BaseConfigurationFileAnalyzer
    {
        public ConcurrentStack<DiagnosticInfo> VulnerableAdditionalText { get; } = new ConcurrentStack<DiagnosticInfo>();

        public IEnumerable<ConfigurationFile> ConfigurationFiles { get; set; }
    }
}