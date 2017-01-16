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

using System.Linq;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;

namespace Puma.Security.Rules.Test.Helpers
{
    /// <summary>
    ///     Helper class to bundle together information about a piece of analyzed test code.
    /// </summary>
    public class TestCode
    {
        public TestCode(string textWithMarker, params MetadataReference[] references)
        {
            // $ marks the position in source code. It's better than passing a manually calculated
            // int, and is just for test convenience. $ is a char that is used nowhere in the C#
            // language.
            Position = textWithMarker.IndexOf('$');
            if (Position != -1)
            {
                textWithMarker = textWithMarker.Remove(Position, 1);
            }

            Text = textWithMarker;
            SyntaxTree = SyntaxFactory.ParseSyntaxTree(Text);

            if (Position != -1)
            {
                Token = SyntaxTree.GetRoot().FindToken(Position);
                SyntaxNode = Token.Parent;
            }

            var listArgs = references.ToList();
            listArgs.Add(MetadataReference.CreateFromFile(typeof(object).Assembly.Location));

            Compilation = CSharpCompilation
                .Create("test")
                .AddSyntaxTrees(SyntaxTree)
                .AddReferences(listArgs.ToArray());

            SemanticModel = Compilation.GetSemanticModel(SyntaxTree);
        }

        public TestCode(string textWithMarker) : this(textWithMarker, MetadataReference.CreateFromFile(typeof(object).Assembly.Location))
        {
          
        }

        public int Position { get; }
        public string Text { get; }

        public SyntaxTree SyntaxTree { get; }

        public SyntaxToken Token { get; }
        public SyntaxNode SyntaxNode { get; private set; }

        public Compilation Compilation { get; }
        public SemanticModel SemanticModel { get; private set; }

        public void GetStatementsBetweenMarkers(out StatementSyntax firstStatement, out StatementSyntax lastStatement)
        {
            var span = GetSpanBetweenMarkers();
            var statementsInside = SyntaxTree
                .GetRoot()
                .DescendantNodes(span)
                .OfType<StatementSyntax>()
                .Where(s => span.Contains(s.Span));
            var first = firstStatement = statementsInside
                .First();
            lastStatement = statementsInside
                .Where(s => s.Parent == first.Parent)
                .Last();
        }

        public TextSpan GetSpanBetweenMarkers()
        {
            var startComment = SyntaxTree
                .GetRoot()
                .DescendantTrivia()
                .First(syntaxTrivia => syntaxTrivia.ToString().Contains("start"));
            var endComment = SyntaxTree
                .GetRoot()
                .DescendantTrivia()
                .First(syntaxTrivia => syntaxTrivia.ToString().Contains("end"));

            var textSpan = TextSpan.FromBounds(
                startComment.FullSpan.End,
                endComment.FullSpan.Start);
            return textSpan;
        }
    }
}