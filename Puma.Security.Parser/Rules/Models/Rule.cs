/*
 * Copyright(c) 2016 - 2020 Puma Security, LLC (https://pumasecurity.io)
 *
 * Project Leads:
 * Eric Johnson (eric.johnson@pumascan.com)
 * Eric Mead (eric.mead@pumascan.com)
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace Puma.Security.Parser.Rules.Models
{
    public class Rule
    {
        public Rule()
        {
        }

        public Rule(string id, string anchor, string title, string category, string message
            , string description, string recommendation, ReportSeverity riskRating, DiagnosticSeverity severity)
        {
            this.Id = id;
            this.Anchor = anchor;
            this.Title = title;
            this.Category = category;
            this.Message = message;
            this.Description = description;
            this.Recommendation = recommendation;
            this.DefaultRiskRating = riskRating;
            this.Severity = severity;

            //New up lists
            this.References = new List<string>();
            this.CodeExamples = new List<Snippet>();
        }

        public string Id { get; set; }

        /// <summary>
        /// Anchor shortcut to the rule docs
        /// </summary>
        public string Anchor { get; set; }

        /// <summary>
        /// Title of the rule (Debug Build Enabled)
        /// </summary>
        public string Title { get; set; }

        /// <summary>
        /// Category name (e.g. Security Misconfiguration, Command Injection)
        /// </summary>
        public string Category { get; set; }

        /// <summary>
        /// Lightweight message displayed in visual studio error window
        /// </summary>
        public string Message { get; set; }

        /// <summary>
        /// Full description of the issue from the web site. Displayed in details view of the error window. Stored in MD format.
        /// </summary>
        public string Description { get; set; }

        /// <summary>
        /// Full recommendation for the issue. Stored in MD format.
        /// </summary>
        public string Recommendation { get; set; }

        /// <summary>
        /// CWE Reference
        /// </summary>
        public CommonWeaknessEnumeration CWE { get; set; }

        /// <summary>
        /// List of URL references (MSDN, OWASP, etc.) on the web site
        /// </summary>
        public List<string> References { get; set; }

        /// <summary>
        /// List of code examples related to the finding and remediation.
        /// </summary>
        public List<Snippet> CodeExamples { get; set; }

        /// <summary>
        /// Default risk rating from the scanner configuration file
        /// </summary>
        [JsonConverter(typeof(StringEnumConverter))]
        public ReportSeverity DefaultRiskRating { get; set; }

        /// <summary>
        /// Helper generating the online URL for help docs
        /// </summary>
        public string Url => $"https://pumascan.com/rules/#{this.Anchor}";

        /// <summary>
        /// Error, Warning, Info bucket for this rule
        /// </summary>
        [JsonConverter(typeof(StringEnumConverter))]
        public DiagnosticSeverity Severity { get; set; }
    }
}