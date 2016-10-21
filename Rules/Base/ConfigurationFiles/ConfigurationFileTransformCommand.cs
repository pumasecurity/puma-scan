using System.IO;
using System.Xml;

using Microsoft.Web.XmlTransform;

namespace Puma.Security.Rules.Base.ConfigurationFiles
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