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

using Microsoft.CodeAnalysis;

namespace Puma.Security.Rules.Model
{
    public class DiagnosticInfo
    {
        public DiagnosticInfo(Location location, params object[] args)
        {
            Args = args;
            Location = location;
        }

        public DiagnosticInfo(string path, int lineNumber, string elementText) : this(Location.None, path, lineNumber,
            elementText)
        {
        }

        public DiagnosticInfo(string path, int lineNumber, string elementText, string arg) : this(Location.None, path,
            lineNumber, elementText, arg)
        {
        }

        public DiagnosticInfo(string path, int lineNumber, string elementText, params object[] args) : this(
            Location.None, path, lineNumber, elementText, args)
        {
        }

        public object[] Args { get; }

        public Location Location { get; }
    }
}