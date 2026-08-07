/*
 * Copyright(c) 2016 - 2026 Puma Security, LLC (https://pumasecurity.io)
 *
 * Project Leads:
 * Eric Johnson (eric.johnson@pumascan.com)
 * Eric Mead (eric.mead@pumascan.com)
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

using System;
using System.Collections.Generic;
using System.Text;

namespace Puma.Security.Parser.Models
{
    internal enum ErrorCode : int
    {
        Success = 0,
        ErrorThreshold = 1,

        InvalidArguments = 1000,
        Exception = 1001,
    }
}
