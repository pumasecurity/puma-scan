﻿/*
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

using CommandLine;
using Microsoft.CodeAnalysis.Sarif.Writers;
using Newtonsoft.Json;
using Puma.Security.Parser.Log;
using Puma.Security.Parser.Models;
using Puma.Security.Parser.Sarif;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using Puma.Security.Parser.Rules;
using Puma.Security.Parser.Rules.Models;

namespace Puma.Security.Parser
{
    public class Program
    {
        public static void Main(string[] args)
        {
#if DEBUG
            Console.Write("Waiting for debugger");
            int maxAttempts = 15;
            int attempts = 0;

            while (!Debugger.IsAttached && attempts < maxAttempts)
            {
                Console.Write(".");
                attempts++;
                Thread.Sleep(TimeSpan.FromSeconds(1));
            }

            Console.WriteLine();

            if (attempts == maxAttempts)
            {
                Console.WriteLine("No debugger attached. Proceeding...");
            }
#endif

            ErrorCode status = ErrorCode.Success;

            //Read cmd line args
            Options o = parseArgs(args);

            if (o == null)
            {
                status = ErrorCode.InvalidArguments;
                Environment.Exit((int)status);
            }

            try
            {
                //Parse instances from the build file
                PumaLog instances = parseBuildWarnings(o);

                //Get Rule Metadata
                RuleProvider ruleProvider = new RuleProvider();
                var rules = ruleProvider.GetRules();

                //Write instances to disk in the requested format
                exportInstances(o, instances, rules);

                //Check threhold requirements
                if (o.Errors != null & o.Errors.Count() > 0)
                {
                    foreach (string error in o.Errors)
                    {
                        if (instances.Any(i => i.RuleId.Equals(error)))
                        {
                            status = ErrorCode.ErrorThreshold;
                            Console.WriteLine($"Error threshold violation: {error}");
                            Console.WriteLine($"Exit code: {(int)status} - {status}");
                            Environment.Exit((int)status);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception: {ex.ToString()}");
                Console.WriteLine($"Exit code: {(int)status} - {status}");
                Environment.Exit((int)status);
            }
        }

        private static Options parseArgs(string[] args)
        {
            ParserResult<Options> result = CommandLine.Parser.Default.ParseArguments<Options>(args);

            if (result.Tag == CommandLine.ParserResultType.NotParsed)
            {
                return null;
            }
            else
            {
                var parsedResult = result as Parsed<Options>;
                return parsedResult.Value;
            }
        }

        private static PumaLog parseBuildWarnings(Options o)
        {
            PumaLog instancelog = new PumaLog();

            using (FileStream stream = new FileStream(o.BuildFile, FileMode.Open))
            {
                using (StreamReader reader = new StreamReader(stream))
                {
                    string line = null;
                    while ((line = reader.ReadLine()) != null)
                    {
                        PumaLogEntry instance = parseWarning(line);
                        if (instance != null)
                            instancelog.Add(instance);
                    }

                    //Kill the stream
                    reader.Dispose();
                }

                //Kill the stream
                stream.Dispose();
            }

            return instancelog;
        }

        private static PumaLogEntry parseWarning(string value)
        {
            //Cateogy must be for Puma (SEC####)
            if (!Regex.IsMatch(value, RegexConstants._REGEX_PUMA_CATEGORY))
                return null;

            //Split the value on ": " to start processing
            string[] parts = Regex.Split(value, RegexConstants._REGEX_WARNING_DELIMITER);

            //Bail out if malformed
            if (parts.Length == 0 || parts.Length < 3)
                return null;

            //Check the first part for a valid path (code warning) or missing data (non-code warning)
            Match mLocalPath = Regex.Match(parts[0], RegexConstants._REGEX_VS_RELATIVE_PATH);
            PumaLogEntry i = mLocalPath.Success ? parseCodeWarning(parts) : parseNonCodeWarning(parts);
            return i;
        }

        private static PumaLogEntry parseCodeWarning(string[] values)
        {
            /*
             * Example code warning
             * 1) Controllers\EmailTemplate\AttachmentService.cs(40,13): warning SEC0112: Unvalidated file paths are passed to a File API, which can allow unauthorized file system operations (e.g. read, write, delete) to be performed on unintended server files. [C:\Jenkins\workspace\Phisherman\Phisherman.Web\Phisherman.Web.csproj]
             */
            Match mLocalPath = Regex.Match(values[0], RegexConstants._REGEX_VS_RELATIVE_PATH);
            if (!mLocalPath.Success)
                return null;

            PumaLogEntry i = new PumaLogEntry();

            //PART 1: Parse path, line, column from the local vs path
            string path = "";
            int lineNumber = 0;
            int columnNumber = 0;
            if (parseVisualStudioPath(mLocalPath.Value, out path, out lineNumber, out columnNumber))
            {
                i.Path = path;
                i.LineNumber = lineNumber;
                i.ColumnNumber = columnNumber;
            }

            //PART 2: Parse category
            Match mCategory = Regex.Match(values[1], RegexConstants._REGEX_PUMA_ERROR_CODE);
            if (mCategory.Success)
                i.RuleId = mCategory.Value;

            var mSeverity = Regex.Match(values[1], RegexConstants._REGEX_RULE_SEVERITY);
            if (mSeverity.Success)
                i.RuleSeverity = mSeverity.Value;

            //PART 3: Parse message and project
            string[] messages = values[2].Split(RegexConstants._VS_PROJECT_DELIMETER_OPEN);
            if (messages.Length != 2)
                return null;

            i.Message = messages[0];
            i.Project = messages[1].TrimEnd(RegexConstants._VS_PROJECT_DELIMETER_CLOSE);
            return i;
        }

        private static PumaLogEntry parseNonCodeWarning(string[] values)
        {
            /* Example non-code warning
             * CSC : warning SEC0013: Pages ViewStateEncryptionMode disabled. C:\Jenkins\workspace\Phisherman\Phisherman.Web\Web.config(39): <pages> [C:\Jenkins\workspace\Phisherman\Phisherman.Web\Phisherman.Web.csproj]
             */
            PumaLogEntry i = new PumaLogEntry();

            //PART 2: Parse category
            Match mCategory = Regex.Match(values[1], RegexConstants._REGEX_PUMA_ERROR_CODE);
            if (mCategory.Success)
                i.RuleId = mCategory.Value;

            //PART 3: Parse message
            string[] messageMatches = Regex.Split(values[2], RegexConstants._REGEX_FULL_WIN_FILE_PATH, RegexOptions.IgnoreCase);
            if (messageMatches.Length > 0)
                i.Message = messageMatches[0].Trim();

            //PART 4: Parse project
            Match mProject = Regex.Match(values[3], RegexConstants._REGEX_FULL_WIN_FILE_PATH);
            if (mProject.Success)
                i.Project = mProject.Value;

            //PART 3 CONTINUED: Parse path and line number
            Match mFilePath = Regex.Match(values[2], RegexConstants._REGEX_FULL_WIN_FILE_PATH, RegexOptions.IgnoreCase);
            if (mFilePath.Success)
            {
                string path = "";
                int lineNumber = 0;
                int columnNumber = 0;
                if (parseVisualStudioPath(mFilePath.Value, out path, out lineNumber, out columnNumber))
                {
                    i.Path = path;
                    i.LineNumber = lineNumber;
                    i.ColumnNumber = columnNumber;
                }
            }

            //PART 3: FINAL: Make path relative to project root
            Match mProjectDir = Regex.Match(i.Project, RegexConstants._REGEX_WIN_DIRECTORY, RegexOptions.IgnoreCase);
            if (mProject.Success)
                i.Path = i.Path.Replace(mProjectDir.Value, "");

            return i;
        }

        private static bool parseVisualStudioPath(string value, out string path, out int lineNumber, out int columnNumber)
        {
            path = "";
            lineNumber = 0;
            columnNumber = 0;

            string[] parts = value.Split(RegexConstants._VS_PATH_DELIMETER_OPEN);

            if (parts.Length != 2)
                return false;

            //Set path to the first part
            path = parts[0];

            //Split path from location using the comma
            string[] locations = parts[1].TrimEnd(RegexConstants._VS_PATH_DELIMETER_CLOSE).Split(RegexConstants._VS_LOCATION_DELIMETER);

            //Grab line number and column number
            if (locations.Length == 0)
                return false;

            if (locations.Length > 0)
                int.TryParse(locations[0], out lineNumber);

            if (locations.Length > 1)
                int.TryParse(locations[1], out columnNumber);

            return true;
        }

        private static void exportToSarifFormat(PumaLog pumaLog, string outputFileName, IEnumerable<Rule> rules)
        {
            using (var outputTextStream = File.Create(outputFileName))
            using (var outputTextWriter = new StreamWriter(outputTextStream))
            using (var outputJson = new JsonTextWriter(outputTextWriter))
            {
                outputJson.Formatting = Formatting.Indented;

                using (var output = new ResultLogJsonWriter(outputJson))
                {
                    PumaLogConverter converter = new PumaLogConverter();
                    converter.Convert(pumaLog, output, rules);
                }
            }
        }

        private static void exportToTextFile(PumaLog pumaLog, string outputFile)
        {
            using (FileStream stream = new FileStream(outputFile, FileMode.CreateNew))
            {
                using (StreamWriter writer = new StreamWriter(stream))
                {
                    foreach (PumaLogEntry pumaLogEntry in pumaLog)
                    {
                        string warning = getBuildWarning(pumaLogEntry);
                        writer.Write(warning);
                        writer.WriteLine();
                    }

                    //Kill the stream
                    writer.Flush();
                    writer.Dispose();
                }

                //Kill the stream
                stream.Dispose();
            }
        }

        private static void exportInstances(Options options, PumaLog pumaLog, IEnumerable<Rule> rules)
        {
            var outputFullPath = Path.Combine(options.Workspace, options.OutputFile);

#if DEBUG
            File.Delete(outputFullPath);
#endif

            if (File.Exists(outputFullPath))
            {
                Console.WriteLine($"Output file already exists at location {outputFullPath}");
                return;
            }

            switch (options.ReportFormat)
            {
                case ReportFormat.MSBuild:
                    exportToTextFile(pumaLog, outputFullPath);
                    break;

                case ReportFormat.Sarif:
                    exportToSarifFormat(pumaLog, outputFullPath, rules);
                    break;
                default:
                    Console.WriteLine("Unsupported Report format.");
                    break;
            }
        }

        private static string getBuildWarning(PumaLogEntry i)
        {
            return string.Format(RegexConstants._MS_BUILD_WARNING_FORMAT, i.Path, i.LineNumber, i.ColumnNumber, i.RuleId, i.Message, i.Project);
        }
    }
}