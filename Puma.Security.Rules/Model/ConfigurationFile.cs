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
using System.Xml.Linq;

using Microsoft.CodeAnalysis;

namespace Puma.Security.Rules.Model
{
    [Serializable]
    public class ConfigurationFile
    {
        public string BaseConfigurationPath { get; set; }

        public string ProductionTransformPath { get; set; }

        public string ProductionConfigurationPath { get; set; }

        public XDocument BaseConfigurationDocument { get; set; }

        public XDocument ProductionConfigurationDocument { get; set; }

        public AdditionalText Source { get; set; }

        public DateTime Created { get; set; }
    }
}