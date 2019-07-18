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

using System;
using System.Linq;

using Puma.Security.Rules.Diagnostics;

namespace Puma.Security.Rules.Common.Extensions
{
    internal static class DiagnosticIdExtensions
    {
        /// <summary>
        ///     Gets the diagnostic id from the given type's SupportedDiagnosticAttribute attribute data
        /// </summary>
        /// <param name="type"></param>
        /// <returns></returns>
        internal static DiagnosticId GetDiagnosticId(this Type type)
        {
            var supportedDiagnosticAttribute = type
                .GetCustomAttributes(typeof(SupportedDiagnosticAttribute), true)
                .FirstOrDefault() as SupportedDiagnosticAttribute;

            var diagnosticId = DiagnosticId.None;
            Enum.TryParse(supportedDiagnosticAttribute.Code, out diagnosticId);
            return diagnosticId;
        }
    }
}