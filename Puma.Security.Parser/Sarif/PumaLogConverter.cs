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

using Microsoft.CodeAnalysis.Sarif;
using Puma.Security.Parser.Log;
using System;
using System.Collections.Generic;
using System.IO;

namespace Puma.Security.Parser.Sarif
{
    public class PumaLogConverter
    {
        public void Convert(PumaLog pumaLog, IResultLogWriter output)
        {
            pumaLog = pumaLog ?? throw new ArgumentNullException(nameof(pumaLog));
            output = output ?? throw new ArgumentNullException(nameof(output));

            var run = new Run()
            {
                Tool = new Tool
                {
                    Name = "Puma Scan"
                }
            };

            output.Initialize(run);

            var results = new List<Result>();
            foreach (PumaLogEntry entry in pumaLog)
            {
                results.Add(CreateResult(entry));
            }

            output.OpenResults();
            output.WriteResults(results);
            output.CloseResults();
        }

        internal Result CreateResult(PumaLogEntry pumaLogEntry)
        {
            pumaLogEntry = pumaLogEntry ?? throw new ArgumentNullException(nameof(pumaLogEntry));

            Result result = new Result()
            {
                RuleId = pumaLogEntry.RuleId,
                Message = new Message { Text = pumaLogEntry.Message }
            };

            switch (pumaLogEntry.RuleSeverity.ToUpper())
            {
                case "ERROR":
                    result.Level = ResultLevel.Error;
                    break;

                case "WARN":
                case "WARNING":
                    result.Level = ResultLevel.Warning;
                    break;

                case "DEFAULT":
                default:
                    result.Level = ResultLevel.Note;
                    break;
            }
            result.Level = ResultLevel.Warning;

            Region region = new Region()
            {
                StartLine = pumaLogEntry.LineNumber + 1,
                StartColumn = pumaLogEntry.ColumnNumber + 1,
            };

            Uri analysisTargetUri = new Uri(Path.Combine(Path.GetDirectoryName(pumaLogEntry.Project), pumaLogEntry.Path), UriKind.Relative);

            var physicalLocation = new PhysicalLocation(id: 0, fileLocation: new FileLocation(uri: analysisTargetUri, uriBaseId: null), region: region, contextRegion: null);
            Location location = new Location()
            {
                PhysicalLocation = physicalLocation
            };

            result.Locations = new List<Location>()
            {
                location
            };

            return result;
        }
    }
}