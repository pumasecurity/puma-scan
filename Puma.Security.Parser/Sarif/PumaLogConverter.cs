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

using Microsoft.CodeAnalysis.Sarif;
using Puma.Security.Parser.Log;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Rule = Puma.Security.Parser.Rules.Models.Rule;

namespace Puma.Security.Parser.Sarif
{
    public class PumaLogConverter
    {
        public void Convert(PumaLog pumaLog, IResultLogWriter output, IEnumerable<Rule> rules)
        {
            pumaLog = pumaLog ?? throw new ArgumentNullException(nameof(pumaLog));
            output = output ?? throw new ArgumentNullException(nameof(output));

            var toolComponent = new ToolComponent()
            {
                Name = "Puma Scan"
            };

            var tool = new Tool //TODO: can create from DLL, Tool.CreateFromAssemblyData() 
            {
                Driver = toolComponent
            };

            var run = new Run()
            {
                Tool = tool
            };

            var toolComponentRules = CreateRules(pumaLog, rules);
            toolComponent.Rules = toolComponentRules;

            output.Initialize(run);

            var results = new List<Result>();
            foreach (PumaLogEntry entry in pumaLog)
            {
                results.Add(CreateResult(entry, toolComponentRules));
            }

            output.OpenResults();
            output.WriteResults(results);
            output.CloseResults();
        }

        private static string parseMessage(string message)
        {
            //Trim the filled in file path, line contents from additional files
            if (System.Text.RegularExpressions.Regex.IsMatch(message, RegexConstants._REGEX_ADDITIONAL_FILES_PATH))
            {
                string[] args = System.Text.RegularExpressions.Regex.Split(message, RegexConstants._REGEX_ADDITIONAL_FILES_PATH);

                if (args.Count() > 0)
                    message = args[0];
            }

            //For rules w/ no findings, trim the placeholders for additional files
            if (System.Text.RegularExpressions.Regex.IsMatch(message, RegexConstants._REGEX_ADDITIONAL_FILES_METADATA))
            {
                string[] args = System.Text.RegularExpressions.Regex.Split(message, RegexConstants._REGEX_ADDITIONAL_FILES_METADATA);

                if (args.Count() > 0)
                    message = args[0];
            }

            return message.Replace("\r\n", string.Empty).Trim();
        }

        private IList<ReportingDescriptor> CreateRules(PumaLog pumaLog, IEnumerable<Rule> pumaRules)
        {
            var result = new List<ReportingDescriptor>();

            foreach (var log in pumaLog)
            {
                var matchingRule = pumaRules.FirstOrDefault(p => p.Id == log.RuleId);

                var reportingDescriptor = new ReportingDescriptor()
                {
                    Id = matchingRule.Id
                };


                reportingDescriptor.DefaultConfiguration = new ReportingConfiguration()
                    {Level = GetHighestLevel(pumaLog, log.RuleId)};

                reportingDescriptor.Name = matchingRule.Title;
                reportingDescriptor.HelpUri = new Uri(matchingRule.Url);

                var fullDescription = new MultiformatMessageString();
                fullDescription.Text = matchingRule.Description;
                
                reportingDescriptor.FullDescription = fullDescription;

                var shortDescription = new MultiformatMessageString();
                shortDescription.Text = parseMessage(matchingRule.Message);
                reportingDescriptor.ShortDescription = shortDescription;

                if(matchingRule.CWE != null)
                    reportingDescriptor.Tags.Add($"CWE-{matchingRule.CWE.Id}: {matchingRule.CWE.Name}");
                result.Add(reportingDescriptor);
            }

            return result;
        }

        internal FailureLevel GetHighestLevel(PumaLog pumaLog, string ruleId)
        {
            var pumaLogInstances = pumaLog.Where(p => p.RuleId == ruleId).ToList();
            if (pumaLogInstances.Any(p => p.RuleSeverity.ToUpper() == "ERROR"))
                return FailureLevel.Error;

            if (pumaLogInstances.Any(p => p.RuleSeverity.ToUpper() == "WARN" || p.RuleSeverity.ToUpper() == "WARNING"))
                return FailureLevel.Warning;

            return FailureLevel.Note;
        }

        internal Result CreateResult(PumaLogEntry pumaLogEntry, IList<ReportingDescriptor> foundRules)
        {
            pumaLogEntry = pumaLogEntry ?? throw new ArgumentNullException(nameof(pumaLogEntry));

            var currentRule = foundRules.FirstOrDefault(p => p.Id == pumaLogEntry.RuleId);

            Result result = new Result()
            {
                RuleId = pumaLogEntry.RuleId,
                Message = new Message
                {
                    Text = currentRule != null ? currentRule.ShortDescription.Text : pumaLogEntry.Message
                }
            };

            switch (pumaLogEntry.RuleSeverity.ToUpper())
            {
                case "ERROR":
                    result.Level = FailureLevel.Error;
                    break;

                case "WARN":
                case "WARNING":
                    result.Level = FailureLevel.Warning;
                    break;

                case "DEFAULT":
                default:
                    result.Level = FailureLevel.Note;
                    break;
            }
            result.Level = FailureLevel.Warning;

            Region region = new Region()
            {
                StartLine = pumaLogEntry.LineNumber + 1,
                StartColumn = pumaLogEntry.ColumnNumber + 1,
            };
            
            Uri analysisTargetUri = new Uri(Path.Combine(Path.GetDirectoryName(pumaLogEntry.Project), pumaLogEntry.Path), UriKind.Absolute);
            var artifactLocation = new ArtifactLocation();
            artifactLocation.Uri = analysisTargetUri;

            // TODO: this will probably need some tweaking since FileLocation is now gone
            var physicalLocation = new PhysicalLocation(null, artifactLocation, region, null, null);

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