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
    public class CommonWeaknessEnumeration
    {
        public CommonWeaknessEnumeration(string id, string name)
        {
            this.Id = id;
            this.Name = name;
        }

        public string Id { get; set; }

        public string Name { get; set; }

        public string Url => $"https://cwe.mitre.org/data/definitions/{Id}.html";

        public CommonWeaknessEnumeration Clone()
        {
            return new CommonWeaknessEnumeration(this.Id, this.Name);
        }
    }
}