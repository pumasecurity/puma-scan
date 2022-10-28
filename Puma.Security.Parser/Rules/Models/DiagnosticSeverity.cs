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

namespace Puma.Security.Parser.Rules.Models
{
    public enum DiagnosticSeverity
    {
        /// <summary>
        /// Something that is an issue, as determined by some authority,
        /// but is not surfaced through normal means.
        /// There may be different mechanisms that act on these issues.
        /// </summary>
        Hidden,
        /// <summary>
        /// Information that does not indicate a problem (i.e. not prescriptive).
        /// </summary>
        Info,
        /// <summary>Something suspicious but allowed.</summary>
        Warning,
        /// <summary>
        /// Something not allowed by the rules of the language or other authority.
        /// </summary>
        Error,
    }
}