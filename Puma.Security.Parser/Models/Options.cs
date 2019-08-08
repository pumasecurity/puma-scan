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

using CommandLine;
using System.Collections.Generic;

namespace Puma.Security.Parser.Models
{

    public enum ReportFormat
    {
        MSBuild,
        Sarif
    }

    public class Options
    {
        [Option('w', "workspace", Required = true, HelpText = "Jenkins workspace root directory")]
        public string Workspace { get; set; }

        [Option('f', "file", Required = true, HelpText = "Build file to parse")]
        public string BuildFile { get; set; }

        [Option('o', "output", Required = true, HelpText = "Output file name")]
        public string OutputFile { get; set; }

        [Option('r', "report", Required = false, HelpText = "Report format. MSBuild or Sarif")]
        public  ReportFormat ReportFormat { get; set; }

        [Option('e', "errors", Required = false, Separator = ',', HelpText = "List of rule ids to be treated as build errors, causing the task to fail. E.g. --errors SEC0029,SEC0108")]
        public IEnumerable<string> Errors { get; set; }
    }
}