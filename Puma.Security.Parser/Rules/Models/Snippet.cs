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
    public class Snippet
    {
        public Snippet(string badge, string content)
        {
            this.Badge = badge;
            this.Content = content;
        }

        /// <summary>
        /// Markdown formatted description of the code example.
        /// </summary>
        public string Badge { get; set; }

        /// <summary>
        /// Code snippet stored in MD.
        /// </summary>
        public string Content { get; set; }

        public Snippet Clone()
        {
            return new Snippet(this.Badge, this.Content);
        }
    }
}