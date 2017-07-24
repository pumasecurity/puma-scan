/* 
 * Copyright(c) 2016 - 2017 Puma Security, LLC (https://www.pumascan.com)
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
using System.Text;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Puma.Security.Rules.Common
{
    public static class Utils
    {
        private static string ARTIFACTS_DIR = "Artifacts";
        
        /// <summary>
        /// Creates a working directory for artifacts being analyzed
        /// </summary>
        /// <param name="assemblyName">Name of the assembly being analyzed</param>
        /// <returns></returns>
        public static string GetWorkingDirectory(string assemblyName)
        {
            string workingPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
               , "Microsoft", "VisualStudio", Assembly.GetExecutingAssembly().GetName().Name, ARTIFACTS_DIR, assemblyName);

            if (!Directory.Exists(workingPath))
                Directory.CreateDirectory(workingPath);

            return workingPath;
        }

        public static string GetCommonRootPath(IEnumerable<AdditionalText> files)
        {
            var paths = from f in files
                        select f.Path;
            return GetCommonRootPath(paths);
        }

        public static string GetCommonRootPath(IEnumerable<string> paths)
        {
            string[] commonPathParts = null;
            int commonPartIndex = int.MaxValue;

            foreach (string path in paths)
            {
                if (!Path.IsPathRooted(path))
                {
                    throw new InvalidOperationException("Only fully qualified path are supported");
                }

                string[] pathParts = path.Split(Path.DirectorySeparatorChar);

                if (commonPathParts == null)
                {
                    commonPathParts = pathParts;
                    commonPartIndex = commonPathParts.Length;
                }
                else
                {
                    int partIndex = 0;
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
            {
                commonPath = string.Empty;
            }
            else if (commonPartIndex == 1)
            {
                commonPath = string.Concat(commonPathParts[0], Path.DirectorySeparatorChar);
            }
            else
            {
                commonPath = string.Join(Path.DirectorySeparatorChar.ToString(), commonPathParts, 0, commonPartIndex);
            }

            return commonPath;
        }

        public static void BinarySerialize(object o, string path)
        {
            //Remove file if it already exists
            if (File.Exists(path))
                File.Delete(path);

            using (Stream stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                IFormatter formatter = new BinaryFormatter();
                formatter.Serialize(stream, o);
                stream.Flush();
                stream.Close();
            }
        }

        public static object BinaryDeserialize(string path)
        {
            object o = null;

            if (!File.Exists(path))
                return null;

            using (Stream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                IFormatter formatter = new BinaryFormatter();
                o = formatter.Deserialize(stream);
                stream.Close();
            }

            return o;
        }

        public static bool SymbolInheritsFrom(INamedTypeSymbol symbol, string baseTypeFullName)
        {
            while (true)
            {
                //Check the symbol type
                if (string.Compare(symbol.ToString(), baseTypeFullName, StringComparison.Ordinal) == 0)
                {
                    return true;
                }

                //If no match, walk up the chain to the base type
                if (symbol.BaseType != null)
                {
                    symbol = symbol.BaseType;
                    continue;
                }

                //Break when the base type hits null
                break;
            }

            return false;
        }

        public static bool IsXssWhiteListedType(ISymbol type)
        {
            var typeToCheck = type;
            if (type.Name.ToLower() == "nullable")
            {
                var namedType = type as INamedTypeSymbol;
                if (namedType == null)
                    return false;

                var ctor = namedType.Constructors.FirstOrDefault(p => p.Parameters.Length > 0);
                if (ctor != null)
                {
                    typeToCheck = ctor.Parameters[0].Type;
                }
            }

            switch (typeToCheck.Name.ToLower())
            {
                case "decimal":
                case "datetime":
                case "datetimeoffset":
                case "int16":
                case "int32":
                case "int64":
                case "double":
                    return true;
                default:
                    break;
            }
            return false;
        }

        /// <summary>
        /// Returns the entire declaration that contains an object create expression. Helps underline the entire line, rather than just a creation expression (right side) of a line.
        /// </summary>
        /// <param name="syntax"></param>
        /// <returns></returns>
        public static LocalDeclarationStatementSyntax GetParentLocalDeclarationStatement(ObjectCreationExpressionSyntax syntax)
        {
            var item = syntax.Parent;

            while (true)
            {
                //Break if the item is null
                if (item == null)
                {
                    break;
                }

                //Check the type
                if (item is LocalDeclarationStatementSyntax)
                {
                    return item as LocalDeclarationStatementSyntax;
                }

                //If no good, walk up the chain to the next parent
                if (item.Parent != null)
                {
                    item = item.Parent;
                    continue;
                }
            }

            return null;
        }
    }
}
