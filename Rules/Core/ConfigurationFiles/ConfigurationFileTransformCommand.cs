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

using System.IO;
using System.Xml;

using Microsoft.Web.XmlTransform;

namespace Puma.Security.Rules.Core.ConfigurationFiles
{
    public interface IConfigurationFileTransformCommand
    {
        void Execute(Model.ConfigurationFile file);
    }

    public class ConfigurationFileTransformCommand : IConfigurationFileTransformCommand
    {
        public void Execute(Model.ConfigurationFile file)
        {
            var fiProductionConfigurationPath = new FileInfo(file.ProductionConfigurationPath);

            //Remove old file if one exists
            if (fiProductionConfigurationPath.Exists)
                fiProductionConfigurationPath.Delete();

            //Apply the transform and save to disk
            XmlTransformableDocument doc = transformConfigurationFile(file.BaseConfigurationPath, file.ProductionTransformPath);
            doc.Save(file.ProductionConfigurationPath);
        }

        private XmlTransformableDocument transformConfigurationFile(string baseConfigurationPath, string transformFilePath)
        {
            using (XmlTransformableDocument doc = new XmlTransformableDocument())
            {
                //Disable DTD's and external entities
                XmlReaderSettings settings = new XmlReaderSettings();
                settings.DtdProcessing = DtdProcessing.Prohibit;
                doc.PreserveWhitespace = true;
                doc.XmlResolver = null;

                //Configure reader settings
                using (XmlReader reader = XmlReader.Create(baseConfigurationPath, settings))
                {
                    //Load the document
                    doc.Load(reader);

                    //Transform the doc
                    using (XmlTransformation transform = new XmlTransformation(transformFilePath))
                    {
                        var success = transform.Apply(doc);
                    }
                }

                return doc;
            }
        }
    }
}