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

using Newtonsoft.Json;
using Puma.Security.Parser.Rules.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

namespace Puma.Security.Parser.Rules
{
    internal class RuleProvider : IRuleProvider
    {
        private static readonly string RULE_FILE_NAMESPACE = "Puma.Security.Parser.Configuration.Rules.json";

        public IEnumerable<Rule> GetRules()
        {
            var assembly = Assembly.GetExecutingAssembly();
            string content;

            Stream stream = null;
            try
            {
                stream = assembly.GetManifestResourceStream(RULE_FILE_NAMESPACE);
                using (var reader = new StreamReader(stream))
                {
                    content = reader.ReadToEnd();
                }
            }
            finally
            {
                stream?.Dispose();
            }

            return JsonConvert.DeserializeObject<List<Rule>>(content, new JsonSerializerSettings
            {
                Error = OnSerializationError,
                MissingMemberHandling = MissingMemberHandling.Ignore,
                NullValueHandling = NullValueHandling.Ignore,
            });
        }

        private static void OnSerializationError(object sender, Newtonsoft.Json.Serialization.ErrorEventArgs args)
        {
            Console.WriteLine(args.ErrorContext.Error.Message);
            args.ErrorContext.Handled = true;
        }
    }
}
