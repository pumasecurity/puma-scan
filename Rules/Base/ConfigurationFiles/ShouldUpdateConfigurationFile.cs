using System.IO;

namespace Puma.Security.Rules.Base.ConfigurationFiles
{
    public interface IShouldUpdateConfigurationFile
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