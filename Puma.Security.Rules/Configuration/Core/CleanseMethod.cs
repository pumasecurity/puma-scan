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

using Puma.Security.Rules.Common;
using System.Collections.Generic;

namespace Puma.Security.Rules.Configuration.Core
{
    public class CleanseMethod
    {
        public CleanseMethod() { }
        public CleanseMethod(TaintFlags flag, string syntax,
            string _namespace, string type, string method) : this(flag, syntax, _namespace, type, method, new List<DiagnosticId>()) { }

        public CleanseMethod(TaintFlags flag, string syntax,
            string _namespace, string type, string method, List<DiagnosticId> ruleIds)
        {
            this.Flag = flag;
            this.Syntax = syntax;
            this.Namespace = _namespace;
            this.Type = type;
            this.Method = method;
            this.RuleIds = ruleIds;
        }

        /// <summary>
        /// List of associated diagnostic ids (defualt of *)
        /// </summary>
        public List<DiagnosticId> RuleIds { get; set; }

        /// <summary>
        /// Taint flag type (Web, Web service, Database)
        /// </summary>
        public TaintFlags Flag { get; set; }

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
        /// ISymbol GetMethod
        /// E.G. System.Web.HttpRequest.Cookies.get would get "get". Wildcard of "*" is supported.
        /// </summary>
        public string Method { get; set; }
    }
}
