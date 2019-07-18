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

using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;

using Puma.Security.Rules.Model;

namespace Puma.Security.Rules.Common.Extensions
{
    internal static class ConfigurationFileExtensions
    {
        internal static IXmlLineInfo GetProductionLineInfo(this ConfigurationFile file, XElement element, string xPathExpression)
        {
            //Get the line info from the element
            IXmlLineInfo lineInfo = element;

            //If we are using a transform, we need to identify the element in the base config document
            if (!string.IsNullOrEmpty(file.ProductionTransformPath))
            {
                var lineElement = file.BaseConfigurationDocument.XPathSelectElement(xPathExpression);
                if (lineElement != null)
                    lineInfo = lineElement;
            }

            return lineInfo;
        }
    }
}