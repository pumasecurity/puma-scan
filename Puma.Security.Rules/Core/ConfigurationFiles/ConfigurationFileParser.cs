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
using System.IO;
using System.Xml.Linq;

using Microsoft.CodeAnalysis;

namespace Puma.Security.Rules.Core.ConfigurationFiles
{
    internal interface IConfigurationFileParser
	{
		Model.ConfigurationFile Parse(AdditionalText src, string basePath, string workingDirectory);
	}

    internal class ConfigurationFileParser : IConfigurationFileParser
	{
		private readonly IShouldUpdateConfigurationFile _shouldUpdate;
		private readonly IConfigurationFileTransformCommand _transformer;

	    internal ConfigurationFileParser() : this(new ShouldUpdateConfigurationFile(),
	        new ConfigurationFileTransformCommand())
	    {
	    }

	    private ConfigurationFileParser(IShouldUpdateConfigurationFile shouldUpdate,
			IConfigurationFileTransformCommand transformer)
		{
			_shouldUpdate = shouldUpdate;
			_transformer = transformer;
		}

		public Model.ConfigurationFile Parse(AdditionalText src, string basePath, string workingDirectory)
		{
			var file = new Model.ConfigurationFile();
			//Set the base configuration file properties
			file.Source = src;
			file.BaseConfigurationPath = src.Path;
			file.BaseConfigurationDocument = XDocument.Load(file.BaseConfigurationPath, LoadOptions.SetLineInfo);

            //Construct the path to the prod transform file
		    var productionTransform = string.IsNullOrEmpty(RuleOptions.ProductionBuildConfiguration)
		        ? null
		        : Path.Combine(
		            Path.GetDirectoryName(file.BaseConfigurationPath)
		            , string.Format("{0}.{1}{2}", Path.GetFileNameWithoutExtension(file.BaseConfigurationPath)
		                , RuleOptions.ProductionBuildConfiguration, Path.GetExtension(file.BaseConfigurationPath)));

            //If transform file exists, run the transform and set the prod document
            if (!string.IsNullOrEmpty(productionTransform) && File.Exists(productionTransform))
			{
				//Set the prod transform path
				file.ProductionTransformPath = productionTransform;

				//Set the location of the transformed file
				file.ProductionConfigurationPath = Path.Combine(workingDirectory,
					productionTransform.Replace(basePath, "").Trim(Path.DirectorySeparatorChar));

				if (_shouldUpdate.Execute(file))
				{
					_transformer.Execute(file);
				}

				//Parse the prod transform xml
				file.ProductionConfigurationDocument = XDocument.Load(file.ProductionConfigurationPath,
					LoadOptions.SetLineInfo);
			}
			else
			{
				//No transform file exists, set the defaults
				file.ProductionTransformPath = null;
				file.ProductionConfigurationPath = file.BaseConfigurationPath;
				file.ProductionConfigurationDocument = file.BaseConfigurationDocument;
			}

			//Set the parse timestamp
			file.Created = DateTime.Now;
			return file;
		}
	}
}