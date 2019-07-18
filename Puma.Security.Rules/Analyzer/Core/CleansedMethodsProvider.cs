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
using System.Linq;

using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Common;
using Puma.Security.Rules.Configuration.Core;

namespace Puma.Security.Rules.Analyzer.Core
{
    internal class CleansedMethodsProvider : ICleansedMethodsProvider
    {
        public IEnumerable<CleanseMethod> GetByRuleId(DiagnosticId id)
        {
            //todo: filter by id
            List<CleanseMethod> sources = new List<CleanseMethod>();

            sources.Add(new CleanseMethod(TaintFlags.DataType, typeof(InvocationExpressionSyntax).Name, "System", "Convert", "ToBoolean"));
            sources.Add(new CleanseMethod(TaintFlags.DataType, typeof(InvocationExpressionSyntax).Name, "System", "Convert", "ToDateTime"));
            sources.Add(new CleanseMethod(TaintFlags.DataType, typeof(InvocationExpressionSyntax).Name, "System", "Convert", "ToDecimal"));
            sources.Add(new CleanseMethod(TaintFlags.DataType, typeof(InvocationExpressionSyntax).Name, "System", "Convert", "ToDouble"));
            sources.Add(new CleanseMethod(TaintFlags.DataType, typeof(InvocationExpressionSyntax).Name, "System", "Convert", "ToInt16"));
            sources.Add(new CleanseMethod(TaintFlags.DataType, typeof(InvocationExpressionSyntax).Name, "System", "Convert", "ToInt32"));
            sources.Add(new CleanseMethod(TaintFlags.DataType, typeof(InvocationExpressionSyntax).Name, "System", "Convert", "ToInt64"));
            sources.Add(new CleanseMethod(TaintFlags.DataType, typeof(InvocationExpressionSyntax).Name, "System", "Convert", "ToUInt16"));
            sources.Add(new CleanseMethod(TaintFlags.DataType, typeof(InvocationExpressionSyntax).Name, "System", "Convert", "ToUInt32"));
            sources.Add(new CleanseMethod(TaintFlags.DataType, typeof(InvocationExpressionSyntax).Name, "System", "Convert", "ToUInt64"));

            List<DiagnosticId> antiXssIds = new List<DiagnosticId>();
            antiXssIds.AddRange(new[] { DiagnosticId.SEC0024, DiagnosticId.SEC0100, DiagnosticId.SEC0101, DiagnosticId.SEC0102
                , DiagnosticId.SEC0103, DiagnosticId.SEC0104, DiagnosticId.SEC0105});

            sources.Add(new CleanseMethod(TaintFlags.Web, typeof(InvocationExpressionSyntax).Name, "System.Web.Security.AntiXss", "AntiXssEncoder", "HtmlEncode", antiXssIds));
            sources.Add(new CleanseMethod(TaintFlags.Web, typeof(InvocationExpressionSyntax).Name, "Microsoft.Security.Application", "Encoder", "HtmlEncode", antiXssIds));
            sources.Add(new CleanseMethod(TaintFlags.Web, typeof(InvocationExpressionSyntax).Name, "System.Web", "HttpServerUtility", "HtmlEncode", antiXssIds));


            sources.Add(new CleanseMethod(TaintFlags.Web, typeof(InvocationExpressionSyntax).Name, "Microsoft.Security.Application", "Encoder", "LdapDistinguishedNameEncode", new List<DiagnosticId>() { DiagnosticId.SEC0012 }));

            sources.Add(new CleanseMethod(TaintFlags.Web, typeof(InvocationExpressionSyntax).Name, "Microsoft.Security.Application", "Encoder", "LdapFilterEncode", new List<DiagnosticId>() { DiagnosticId.SEC0012 }));

            sources.Add(new CleanseMethod(TaintFlags.Web, typeof(InvocationExpressionSyntax).Name, "System.Web.Mvc", "UrlHelper", "IsLocalUrl", new List<DiagnosticId>() { DiagnosticId.SEC0109 }));

            sources.Add(new CleanseMethod(TaintFlags.Web, typeof(InvocationExpressionSyntax).Name, "System", "Uri", "TryCreate", new List<DiagnosticId>() { DiagnosticId.SEC0110 }));

            return sources;
        }
    }
}