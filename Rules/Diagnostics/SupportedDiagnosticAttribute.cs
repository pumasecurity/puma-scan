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

using System;

using Puma.Security.Rules.Common;

using Microsoft.CodeAnalysis;

namespace Puma.Security.Rules.Diagnostics
{
    [AttributeUsage(AttributeTargets.Class)]
    public class SupportedDiagnosticAttribute : Attribute
    {
        public SupportedDiagnosticAttribute(DiagnosticId code, DiagnosticSeverity severity = DiagnosticSeverity.Warning,
            DiagnosticCategory category = DiagnosticCategory.Security)
        {
            Code = code.ToString();
            Severity = severity;
            Category = category;
        }

        public DiagnosticCategory Category { get; }

        public DiagnosticSeverity Severity { get; }

        public string Code { get; }

        public DiagnosticDescriptor GetDescriptor()
        {
            return DiagnosticDescriptorFactory.Create(Code, Severity, Category);
        }
    }
}