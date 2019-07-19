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

using System.Collections.Generic;
using System.Collections.Immutable;

using Microsoft.CodeAnalysis;

namespace Puma.Security.Rules.Analyzer.Core
{
    public class VulnerableSyntaxNode
    {
        public VulnerableSyntaxNode(SyntaxNode sink, ImmutableArray<SyntaxNode> source, params string[] messageArgs)
        {
            Source = source;
            Sink = sink;
            MessageArgs = messageArgs;
        }

        public VulnerableSyntaxNode(SyntaxNode sink, ImmutableArray<SyntaxNode> source)
        {
            Source = source;
            Sink = sink;
        }

        public VulnerableSyntaxNode(SyntaxNode sink, params string[] messageArgs)
        {
            Sink = sink;
            MessageArgs = messageArgs;
        }

        public VulnerableSyntaxNode(SyntaxNode sink)
        {   
            Sink = sink;
        }

        public VulnerableSyntaxNode(SyntaxNode sink, SyntaxNode source, params string[] messageArgs)
        {
            Source = new List<SyntaxNode>() { source }.ToImmutableArray();
            Sink = sink;
            MessageArgs = messageArgs;
        }

        public ImmutableArray<SyntaxNode> Source { get; private set; }

        public SyntaxNode Sink { get; private set; }

        public bool Suppressed { get; set; }

        public string[] MessageArgs { get; set; }
    }
}