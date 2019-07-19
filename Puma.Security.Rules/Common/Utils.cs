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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

using Microsoft.CodeAnalysis;


namespace Puma.Security.Rules.Common
{
    public static class Utils
    {
        private static readonly string ARTIFACTS_DIR = "Artifacts";

        /// <summary>
        ///     Creates a working directory for artifacts being analyzed
        /// </summary>
        /// <param name="assemblyName">Name of the assembly being analyzed</param>
        /// <returns></returns>
        internal static string GetWorkingDirectory(string assemblyName)
        {
            var workingPath = Path.Combine(GetPumaLocalAppDataPath(), ARTIFACTS_DIR, assemblyName);

            if (!Directory.Exists(workingPath))
                Directory.CreateDirectory(workingPath);

            return workingPath;
        }

        internal static string GetPumaLocalAppDataPath()
        {
            var filePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
                , "PumaSecurity", "Community");

            if (!Directory.Exists(Path.GetDirectoryName(filePath)))
                Directory.CreateDirectory(Path.GetDirectoryName(filePath));

            return filePath;
        }

        internal static string GetCommonRootPath(IEnumerable<AdditionalText> files)
        {
            var paths = from f in files
                select f.Path;
            return GetCommonRootPath(paths);
        }

        internal static string GetCommonRootPath(IEnumerable<string> paths)
        {
            string[] commonPathParts = null;
            var commonPartIndex = int.MaxValue;

            foreach (var path in paths)
            {
                if (!Path.IsPathRooted(path))
                    throw new InvalidOperationException("Only fully qualified path are supported");

                var pathParts = path.Split(Path.DirectorySeparatorChar);

                if (commonPathParts == null)
                {
                    commonPathParts = pathParts;
                    commonPartIndex = commonPathParts.Length;
                }
                else
                {
                    var partIndex = 0;
                    while (partIndex < pathParts.Length && partIndex < commonPathParts.Length)
                    {
                        if (string.Compare(commonPathParts[partIndex], pathParts[partIndex], true) != 0) break;

                        partIndex++;
                    }

                    commonPartIndex = Math.Min(commonPartIndex, partIndex);
                }
            }

            string commonPath;
            if (commonPartIndex == 0)
                commonPath = string.Empty;
            else if (commonPartIndex == 1)
                commonPath = string.Concat(commonPathParts[0], Path.DirectorySeparatorChar);
            else
                commonPath = string.Join(Path.DirectorySeparatorChar.ToString(), commonPathParts, 0, commonPartIndex);

            return commonPath;
        }
    }
}