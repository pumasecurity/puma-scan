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

using System.Runtime.Serialization;

namespace Puma.Security.Parser.Log
{
    [DataContract]
    public class PumaLogEntry
    {
        [DataMember(Name = "ruleSeverity", IsRequired = true, EmitDefaultValue = true)]
        public string RuleSeverity { get; set; }

        [DataMember(Name = "category", IsRequired = true, EmitDefaultValue = true)]
        public string RuleId { get; set; }

        [DataMember(Name = "path", IsRequired = true, EmitDefaultValue = true)]
        public string Path { get; set; }

        [DataMember(Name = "columnNumber", IsRequired = true, EmitDefaultValue = true)]
        public int ColumnNumber { get; set; }

        [DataMember(Name = "lineNumber", IsRequired = true, EmitDefaultValue = true)]
        public int LineNumber { get; set; }

        [DataMember(Name = "message", IsRequired = true, EmitDefaultValue = true)]
        public string Message { get; set; }

        [DataMember(Name = "project", IsRequired = true, EmitDefaultValue = true)]
        public string Project { get; set; }
    }
}