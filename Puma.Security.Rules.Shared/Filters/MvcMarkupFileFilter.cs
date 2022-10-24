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
using System.Collections.Immutable;
using System.IO;
using System.Linq;

using Microsoft.CodeAnalysis;

namespace Puma.Security.Rules.Filters
{
    internal class MvcMarkupFileFilter : IFileExtensionFilter
    {
        public const string CS_RAZOR_EXTENSION = ".cshtml";
        public const string VB_RAZOR_EXTENSION = ".vbhtml";

        public IEnumerable<AdditionalText> GetFiles(ImmutableArray<AdditionalText> additionalFiles)
        {
            return
                additionalFiles.Where(f => 
                    string.Compare(Path.GetExtension(f.Path), CS_RAZOR_EXTENSION) == 0 ||
                    string.Compare(Path.GetExtension(f.Path), VB_RAZOR_EXTENSION) == 0)
                    .ToList();
        }
    }
}