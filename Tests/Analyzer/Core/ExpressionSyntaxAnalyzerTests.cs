/* 
 * Copyright(c) 2016 - 2017 Puma Security, LLC (https://www.pumascan.com)
 * 
 * Project Leader: Eric Johnson (eric.johnson@pumascan.com)
 * Lead Developer: Eric Mead (eric.mead@pumascan.com)
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

using System;
using System.Linq;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.Security.Application;

using NUnit.Framework;

using Puma.Security.Rules.Analyzer.Core;
using Puma.Security.Rules.Test.Helpers;

namespace Puma.Security.Rules.Test.Analyzer.Core
{
    [TestFixture]
    public class ExpressionSyntaxAnalyzerTests
    {
        [SetUp]
        public void Initialize()
        {
            _analyzer = new ExpressionSyntaxAnalyzer();
        }

        private ExpressionSyntaxAnalyzer _analyzer;

        private static readonly MetadataReference AntiXssEncoder =
            MetadataReference.CreateFromFile(typeof(Encoder).Assembly.Location);

        private const string DefaultUsing = @"using System;";
        private const string MemberAccessExpression = @"
                    public class MockObject
                    {
                        public string Name {get;set;}
                        public MockObject Value {get;set;}
                    }
                    public class MockClass
                    {
                        public string Destination { get; set; }
                        public MockObject Value { get;set; }

                        public MockClass()
                        {
                            Destination = Value.Name;
                        }
                    }";
        private const string BinaryExpressionWithLiteralsAndNonStrings = @"
                    public class MockClass
                    {
                        public string Destination { get; set; }

                        public MockClass()
                        {
                            var i = 0;
                            var d = DateTime.Now;
                            Destination = ""harmless"" + d + "" "" + i;
                        }
                    }";
        private const string StringLiteral = @"
                    public class MockClass
                    {
                        public string Destination { get; set; }

                        public MockClass()
                        {
                            Destination = ""a hardcoded string"";
                        }
                    }";
        private const string StringLiteralFormat = @"
                    public class MockObject
                    {
                        public string Name {get;set;}
                        public Decimal Value {get;set;}
                    }
                    public class MockClass
                    {
                        public string Destination { get; set; }
                        public MockObject Value { get;set; }

                        public MockClass()
                        {
                            Destination = Value.Value.ToString(""C"");
                        }
                    }";
        private const string StringFormatWithNonStringArguments = @"
                   public class MockClass
                    {
                        public MockClass()
                        {
                            Destination = String.Format(""{0}{1}"", DateTime.Now.ToString(""T""), DateTime.Now.ToShortDateString());
                        }

                        public string Destination { get; set; }
                    }";
        private const string NonString = @"public class MockObject
                    {
                        public string Name {get;set;}
                        public Decimal Value {get;set;}
                    }
                    public class MockClass
                    {
                        public string Destination { get; set; }
                        public MockObject Value { get;set; }

                        public MockClass()
                        {
                            Destination = Value.Value.ToString(""C"");
                        }
                    }";

        private const string SafeInvocationMethodExpression = @"public class MockObject
                    {
                        public string Name {get;set;}
                    }
                    public class MockClass
                    {
                        public string Destination { get; set; }
                        public MockObject Value { get;set; }

                        public MockClass()
                        {
                            Destination = Encoder.HtmlEncode(Value.Name);
                        }
                    }";

        private static bool IsAssignmentToDestination(SyntaxNode node)
        {
            var expressionStatementSyntax = node as ExpressionStatementSyntax;
            var assignmentExpressionSyntax = expressionStatementSyntax?.Expression as AssignmentExpressionSyntax;

            var identifierNameSyntax = assignmentExpressionSyntax?.Left as IdentifierNameSyntax;
            if (identifierNameSyntax == null)
                return false;

            return identifierNameSyntax.Identifier.ToString() == "Destination";
        }

        private static ExpressionSyntax GetRightExpressionSyntax(SyntaxTree tree)
        {
            var destinationAssignment = GetNode<ExpressionStatementSyntax>(tree, IsAssignmentToDestination);

            var expression = destinationAssignment.Expression as AssignmentExpressionSyntax;
            var rightSyntax = expression.Right;
            return rightSyntax;
        }

        private static T GetNode<T>(SyntaxTree tree, Func<SyntaxNode, bool> predicate)
        {
            var result = tree.GetRoot().DescendantNodes().FirstOrDefault(predicate);
            try
            {
                return (T) Convert.ChangeType(result, typeof(T));
            }
            catch (InvalidCastException)
            {
                return default(T);
            }
        }

        [TestCase(MemberAccessExpression, false)]
        [TestCase(BinaryExpressionWithLiteralsAndNonStrings, true)]
        [TestCase(StringLiteral, true)]
        [TestCase(StringLiteralFormat, true)]
        [TestCase(StringFormatWithNonStringArguments, true)]
        [TestCase(NonString, true)]
        public void TestCanSuppress(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + code);

            var rightSyntax = GetRightExpressionSyntax(testCode.SyntaxTree);

            var result = _analyzer.CanSuppress(testCode.SemanticModel, rightSyntax);

            Assert.AreEqual(expectedResult, result);
        }

        
        [TestCase(SafeInvocationMethodExpression, true)]
        public void TestCanSuppressSafeExpression(string code, bool expectedResult)
        {
            var testCode = new TestCode(DefaultUsing + "using Microsoft.Security.Application;" + code, AntiXssEncoder);

            var rightSyntax = GetRightExpressionSyntax(testCode.SyntaxTree);

            var result = _analyzer.CanSuppress(testCode.SemanticModel, rightSyntax);

            Assert.AreEqual(expectedResult, result);
        }
    }

    public class MockObject
    {
        public string Name { get; set; }
    }

    public class MockClass
    {
        public MockClass()
        {   
            //Destination = Microsoft.Security.Application.AntiXssEncoder.(Value.Name);//Microsoft.Security.Application.Encoder.HtmlEncode(Value.Name);
            //System.Web.Security.AntiXss.AntiXssEncoder.HtmlEncode(Value.Name);
        }

        public string Destination { get; set; }
        public MockObject Value { get; set; }
    }

//public class MockClass
//{
//    public MockClass()
//    {
//        Destination = string.Format("{0}{1}", DateTime.Now.ToString("T"), DateTime.Now.ToShortDateString());
//    }

//    public string Destination { get; set; }
//}


//public class MockObject
//{
//    public string Name { get; set; }
//    public decimal Value { get; set; }
//}

//public class MockClass
//{
//    public MockClass()
//    {
//        var i = 0;
//        var d = DateTime.Now;
//        Destination = "harmless" + d + " " + i;
//    }

//    public string Destination { get; set; }
//}
}