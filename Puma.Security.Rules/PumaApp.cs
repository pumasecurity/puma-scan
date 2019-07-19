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


namespace Puma.Security.Rules //Root namespace to make globally available
{
    public class PumaApp
    {
        private static PumaApp _pumaApp;

        internal PumaApp()
        {
            this.Id = Guid.NewGuid();

            _pumaApp = this;
        }

        public Guid Id { get; }

        public static PumaApp Instance => _pumaApp;
    }
}