using System;
using System.IO;
using System.Collections.Generic;
using Xunit;
using System.Reflection;

namespace Microsoft.Web.XmlTransform.Test
{
    public class XmlTransformTest
    {
        public XmlTransformTest()
        {
            Cleanup();
        }

        [Fact]
        public void XmlTransform_Support_WriteToStream()
        {
            string src = CreateATestFile("Web.config", Properties.Resources.Web);
            string transformFile = CreateATestFile("Web.Release.config", Properties.Resources.Web_Release);
            string destFile = GetTestFilePath("MyWeb.config");

            //execute
            XmlTransformableDocument x = new XmlTransformableDocument();
            x.PreserveWhitespace = true;
            x.Load(src);

            XmlTransformation transform = new XmlTransformation(transformFile);

            bool succeed = transform.Apply(x);

            FileStream fsDestFile = new FileStream(destFile, FileMode.OpenOrCreate, FileAccess.Write);
            x.Save(fsDestFile);

            //verify, we have a success transform
            Assert.True(succeed);

            //verify, the stream is not closed
            Assert.True(fsDestFile.CanWrite, "The file stream can not be written. was it closed?");

            //sanity verify the content is right, (xml was transformed)
            fsDestFile.Close();
            string content = File.ReadAllText(destFile);
            bool isDebug = content.Contains("debug=\"true\"");
            Assert.False(isDebug);

            List<string> lines = new List<string>(File.ReadLines(destFile));
            //sanity verify the line format is not lost (otherwsie we will have only one long line)
            Assert.True(lines.Count > 10);

            //be nice 
            transform.Dispose();
            x.Dispose();
        }

        [Fact]
        public void XmlTransform_AttibuteFormatting()
        {
            Transform_TestRunner_ExpectSuccess(Properties.Resources.AttributeFormating_source,
                    Properties.Resources.AttributeFormating_transform,
                    Properties.Resources.AttributeFormating_destination,
                    Properties.Resources.AttributeFormatting_log);
        }

        [Fact]
        public void XmlTransform_TagFormatting()
        {
            Transform_TestRunner_ExpectSuccess(Properties.Resources.TagFormatting_source,
                   Properties.Resources.TagFormatting_transform,
                   Properties.Resources.TagFormatting_destination,
                   Properties.Resources.TagFormatting_log);
        }

        [Fact]
        public void XmlTransform_HandleEdgeCase()
        {
            //2 edge cases we didn't handle well and then fixed it per customer feedback.
            //    a. '>' in the attribute value
            //    b. element with only one character such as <p>
            Transform_TestRunner_ExpectSuccess(Properties.Resources.EdgeCase_source,
                    Properties.Resources.EdgeCase_transform,
                    Properties.Resources.EdgeCase_destination,
                    Properties.Resources.EdgeCase_log);
        }

        [Fact]
        public void XmlTransform_ErrorAndWarning()
        {
            Transform_TestRunner_ExpectFail(Properties.Resources.WarningsAndErrors_source,
                    Properties.Resources.WarningsAndErrors_transform,
                    Properties.Resources.WarningsAndErrors_log);
        }

        private void Transform_TestRunner_ExpectSuccess(string source, string transform, string baseline, string expectedLog)
        {
            string src = CreateATestFile("source.config", source);
            string transformFile = CreateATestFile("transform.config", transform);
            string baselineFile = CreateATestFile("baseline.config", baseline);
            string destFile = GetTestFilePath("result.config");
            TestTransformationLogger logger = new TestTransformationLogger();

            bool succeed = false;
            using (XmlTransformableDocument x = new XmlTransformableDocument())
            {
                x.PreserveWhitespace = true;
                x.Load(src);

                succeed = false;
                using (XmlTransformation xmlTransform = new XmlTransformation(transformFile, logger))
                {
                    //execute
                    succeed = xmlTransform.Apply(x);
                    x.Save(destFile);

                    xmlTransform.Dispose();
                    x.Dispose();
                }
            }

            //test
            Assert.True(succeed);
            CompareFiles(destFile, baselineFile);
            CompareMultiLines(expectedLog, logger.LogText);
        }

        private void Transform_TestRunner_ExpectFail(string source, string transform, string expectedLog)
        {
            string src = CreateATestFile("source.config", source);
            string transformFile = CreateATestFile("transform.config", transform);
            string destFile = GetTestFilePath("result.config");
            TestTransformationLogger logger = new TestTransformationLogger();

            XmlTransformableDocument x = new XmlTransformableDocument();
            x.PreserveWhitespace = true;
            x.Load(src);

            XmlTransformation xmlTransform = new XmlTransformation(transformFile, logger);

            //execute
            bool succeed = xmlTransform.Apply(x);
            x.Save(destFile);
            xmlTransform.Dispose();
            x.Dispose();
            //test
            Assert.False(succeed);
            CompareMultiLines(expectedLog, logger.LogText);
        }

        private void CompareFiles(string baseLinePath, string resultPath)
        {
            string bsl;
            using (FileStream stream = new FileStream(baseLinePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                using (StreamReader reader = new StreamReader(stream))
                {
                    bsl = reader.ReadToEnd();
                    reader.Close();
                }
                stream.Close();
            }

            string result;
            using (FileStream stream = new FileStream(resultPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                using (StreamReader reader = new StreamReader(stream))
                {
                    result = reader.ReadToEnd();
                    reader.Close();
                }
                stream.Close();
            }

            CompareMultiLines(bsl, result);
        }

        private void CompareMultiLines(string baseline, string result)
        {
            string[] baseLines = baseline.Split(new string[] { System.Environment.NewLine }, StringSplitOptions.None);
            string[] resultLines = result.Split(new string[] { System.Environment.NewLine }, StringSplitOptions.None);

            for (int i = 0; i < baseLines.Length; i++)
            {
                bool equal = baseLines[i].Equals(resultLines[i]);
                Assert.True(equal, $"Line {i} at baseline file is not matched.{Environment.NewLine}Base: {baseLines[i]}{Environment.NewLine}Resl: {resultLines[i]}");
            }
        }

        private string CreateATestFile(string filename, string contents)
        {
            string file = GetTestFilePath(filename);
            File.WriteAllText(file, contents);
            return file;
        }

        private string GetTestFilePath(string filename)
        {
            string folder = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "XmlTransformTest");
            if (!Directory.Exists(folder))
                Directory.CreateDirectory(folder);
            string file = Path.Combine(folder, filename);
            return file;
        }

        private void Cleanup()
        {
            string folder = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "XmlTransformTest");
            if(Directory.Exists(folder))
            {
                foreach(string file in Directory.EnumerateFiles(folder))
                {
                    File.Delete(file);
                }
            }

        }
    }
}
