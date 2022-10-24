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

using Microsoft.CodeAnalysis;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Puma.Security.Rules.Filters
{
    internal class ConfigurationFileFilter : IFileExtensionFilter
    {
        public const string EXTENSION = ".config";

        public IEnumerable<AdditionalText> GetFiles(ImmutableArray<AdditionalText> additionalFiles)
        {
            return additionalFiles.Where(f => string.Compare(Path.GetExtension(f.Path), EXTENSION) == 0).ToList();
        }
    }
}
