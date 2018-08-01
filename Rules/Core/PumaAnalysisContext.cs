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

using Microsoft.CodeAnalysis.Diagnostics;

namespace Puma.Security.Rules.Core
{
    internal class PumaAnalysisContext
    {
        internal readonly AnalysisContext Context;

        public Guid CompilationId { get; }

        internal PumaAnalysisContext(AnalysisContext context)
        {
            this.CompilationId = Guid.NewGuid();
            this.Context = context;
        }
    }
}