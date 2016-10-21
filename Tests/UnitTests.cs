/* 
 * Copyright(c) 2016 Puma Security, LLC (https://www.pumascan.com)
 * 
 * Project Leader: Eric Johnson (eric.johnson@pumascan.com)
 * Lead Developer: Eric Mead (eric.mead@pumascan.com)
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Puma.Security.Rules;
using System;
using System.IO;
using TestHelper;
using System.Xml;
using System.Xml.XPath;
using System.Linq;
using System.Xml.Linq;
using Microsoft.Web.XmlTransform;
using System.Collections.Generic;

namespace Puma.Security.Rules.Test
{
    [TestClass]
    public class UnitTest : CodeFixVerifier
    {
        
        //No diagnostics expected to show up
        [TestMethod]
        public void TestMethod1()
        {
            var test = @"";

            VerifyCSharpDiagnostic(test);
        }

        //Diagnostic and CodeFix both triggered and checked for
        [TestMethod]
        public void TestMethod2()
        {
            var test = @"
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using System.Diagnostics;

    namespace ConsoleApplication1
    {
        class TypeName
        {   
        }
    }";
            var expected = new DiagnosticResult
            {
                Id = "PumaSecurityRules",
                Message = String.Format("Type name '{0}' contains lowercase letters", "TypeName"),
                Severity = DiagnosticSeverity.Warning,
                Locations =
                    new[] {
                            new DiagnosticResultLocation("Test0.cs", 11, 15)
                        }
            };

            VerifyCSharpDiagnostic(test, expected);
            /*
            var fixtest = @"
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using System.Diagnostics;

    namespace ConsoleApplication1
    {
        class TYPENAME
        {   
        }
    }";
            VerifyCSharpFix(test, fixtest);
            */
        }
        
        [TestMethod]
        public void CreateWorkingDirectoryTest()
        {
            string path = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        }

        [TestMethod]
        public void CreateBasePathTest()
        {
            string configFile = @"C:\Users\Eric\Documents\git.cypressdefense.net\VSSecurityRulePack\Targets\WebFormsTarget\Web.config";
            string dir = Path.GetDirectoryName(configFile);
            DirectoryInfo di = new DirectoryInfo(dir);
            FileInfo[] files = di.GetFiles("*.config", SearchOption.AllDirectories);
            var paths = from f in files
                        select f.FullName;

            string basePath = GetCommonRootPath(paths);

            Assert.IsTrue(true);
        }

        private string GetCommonRootPath(IEnumerable<string> paths)
        {
            string[] commonPathParts = null;
            int commonPartIndex = int.MaxValue;

            foreach (string path in paths)
            {
                if (!Path.IsPathRooted(path))
                {
                    throw new InvalidOperationException("Only fully qualified path are supported");
                }

                string[] pathParts = path.Split(Path.DirectorySeparatorChar);

                if (commonPathParts == null)
                {
                    commonPathParts = pathParts;
                    commonPartIndex = commonPathParts.Length;
                }
                else
                {
                    int partIndex = 0;
                    while (partIndex < pathParts.Length && partIndex < commonPathParts.Length)
                    {
                        if (string.Compare(commonPathParts[partIndex], pathParts[partIndex], StringComparison.OrdinalIgnoreCase) != 0) break;

                        partIndex++;
                    }

                    commonPartIndex = Math.Min(commonPartIndex, partIndex);
                }
            }

            string commonPath;
            if (commonPartIndex == 0)
            {
                commonPath = string.Empty;
            }
            else if (commonPartIndex == 1)
            {
                commonPath = string.Concat(commonPathParts[0], Path.DirectorySeparatorChar);
            }
            else
            {
                commonPath = string.Join(Path.DirectorySeparatorChar.ToString(), commonPathParts, 0, commonPartIndex);
            }

            return commonPath;
        }

        [TestMethod]
        public void ParseCustomErrorsTest()
        {
            XDocument doc = transformConfig(@"..\\..\\..\\..\\Targets\\WebFormsTarget\\Web.config");
            XElement element = doc.XPathSelectElement("configuration/system.web/customErrors");
            Assert.IsNotNull(element);
        
            XAttribute mode = element.Attribute("mode");

            Assert.IsNotNull(mode);
            Assert.AreEqual(mode.Value, "off", true);
            
            IXmlLineInfo lineInfo = mode as IXmlLineInfo;
            int position = lineInfo.LinePosition;
            int lineNumber = lineInfo.LineNumber;

            Assert.AreEqual(16, lineNumber);
        }

        private XDocument transformConfig(string configPath)
        {
            XDocument xDoc = null;

            using (XmlTransformableDocument doc = new XmlTransformableDocument())
            {
                //Disable DTD's and external entities
                XmlReaderSettings settings = new XmlReaderSettings();
                settings.DtdProcessing = DtdProcessing.Prohibit;
                doc.PreserveWhitespace = true;
                doc.XmlResolver = null;

                //Configure reader settings
                using (XmlReader reader = XmlReader.Create(configPath, settings))
                {
                    //Load the document
                    doc.Load(reader);

                    //Construct the matching transform file
                    string productionTransform = Path.Combine(
                        Path.GetDirectoryName(configPath)
                        , string.Format("{0}.{1}{2}", Path.GetFileNameWithoutExtension(configPath), RuleOptions.ProductionBuildConfiguration, Path.GetExtension(configPath)));

                    //Transform the file if it exists
                    if (File.Exists(productionTransform))
                    {
                        using (XmlTransformation transform = new XmlTransformation(productionTransform))
                        {
                            var success = transform.Apply(doc);
                        }
                    }

                    //Write the transformed document out
                    xDoc = XDocument.Load(new XmlNodeReader(doc), LoadOptions.SetLineInfo);
                }

                return xDoc;
            }
        }

        /*
        protected override CodeFixProvider GetCSharpCodeFixProvider()
        {
            return new Provider.ExampleProvider();
        }

        protected override DiagnosticAnalyzer GetCSharpDiagnosticAnalyzer()
        {
            return new Analyzer.ExampleAnalyzer();
        }
        */
    }
}