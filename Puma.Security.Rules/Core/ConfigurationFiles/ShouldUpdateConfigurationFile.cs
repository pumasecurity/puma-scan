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

using System.IO;

namespace Puma.Security.Rules.Core.ConfigurationFiles
{
    internal interface IShouldUpdateConfigurationFile
    {
        bool Execute(Model.ConfigurationFile file);
    }

    public class ShouldUpdateConfigurationFile : IShouldUpdateConfigurationFile
    {
        public bool Execute(Model.ConfigurationFile file)
        {
            var fiBaseConfig = new FileInfo(file.BaseConfigurationPath);
            var fiProductionTransform = new FileInfo(file.ProductionTransformPath);
            var fiProductionConfigurationPath = new FileInfo(file.ProductionConfigurationPath);

            return !fiProductionConfigurationPath.Exists |
                   (fiProductionConfigurationPath.LastWriteTimeUtc < fiBaseConfig.LastWriteTimeUtc) |
                   (fiProductionConfigurationPath.LastWriteTimeUtc < fiProductionTransform.LastWriteTimeUtc);
        }
    }
}