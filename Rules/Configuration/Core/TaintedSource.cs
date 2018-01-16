/* 
 * Copyright(c) 2016 - 2018 Puma Security, LLC (https://www.pumascan.com)
 * 
 * Project Leader: Eric Johnson (eric.johnson@pumascan.com)
 * Lead Developer: Eric Mead (eric.mead@pumascan.com)
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

using Microsoft.CodeAnalysis.CSharp.Syntax;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Puma.Security.Rules.Common;
using System;
using System.Collections.Generic;
using System.Reflection;

namespace Puma.Security.Rules.Configuration.Core
{
    public class TaintedSource
    {
        public TaintedSource() { }
        public TaintedSource(TaintFlags flag, string syntax,
            string _namespace, string type, string property, string method) : this(flag, syntax, _namespace, type, property, method, null) { }

        public TaintedSource(TaintFlags flag, string syntax, 
            string _namespace, string type, string property, string method , string ruleId)
        {
            this.Flag = flag;
            this.Syntax = syntax;
            this.Namespace = _namespace;
            this.Type = type;
            this.Property = property;
            this.Method = method;
            this.RuleIds = new List<DiagnosticId>();
        }
        
        /// <summary>
        /// List of associated diagnostic ids (defualt of *)
        /// </summary>
        [JsonProperty (ItemConverterType = typeof(StringEnumConverter))]
        public List<DiagnosticId> RuleIds { get; set; }
        
        /// <summary>
        /// Taint flag type (Web, Web service, Database)
        /// </summary>
        [JsonConverter(typeof(StringEnumConverter))]
        public TaintFlags Flag { get; set; }
        /// <summary>
        /// Element Kind (ObjectCreationExpression, ElementAccessExpression, etc.)
        /// </summary>
        public string Syntax { get; set; }
        /// <summary>
        /// ISymbol ContainingNamespace
        /// </summary>
        public string Namespace { get; set; }
        /// <summary>
        /// ISymbol ContainingType (Only the type name, not the namespace qualifier in front of it).
        /// E.G. System.Web.HttpRequest would be "HttpRequest". Wildcard of "*" is supported to flag an entire namespace.
        /// </summary>
        public string Type { get; set; }
        /// <summary>
        /// ISymbol Name. Wildcard of "*" is supported.
        /// </summary>
        public string Property { get; set; }
        /// <summary>
        /// ISymbol GetMethod
        /// E.G. System.Web.HttpRequest.Cookies.get would get "get". Wildcard of "*" is supported.
        /// </summary>
        public string Method { get; set; }
    }
}
