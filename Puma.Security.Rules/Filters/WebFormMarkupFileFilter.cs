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
using System.IO;
using System.Linq;

using Microsoft.CodeAnalysis;

namespace Puma.Security.Rules.Filters
{
    internal class WebFormMarkupFileFilter : IFileExtensionFilter
    {
        private const string WEBFORMS_EXTENSION = ".aspx";
        private const string WEBCONTROL_EXTENSION = ".ascx";

        public IEnumerable<AdditionalText> GetFiles(ImmutableArray<AdditionalText> additionalFiles)
        {
            return
                additionalFiles.Where(f => (string.Compare(Path.GetExtension(f.Path), WEBFORMS_EXTENSION, true) == 0) ||
                    (string.Compare(Path.GetExtension(f.Path), WEBCONTROL_EXTENSION, true) == 0)
                ).ToList();
        }
    }
}