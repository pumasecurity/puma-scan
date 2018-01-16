/* 
 * Copyright(c) 2016 - 2018 Puma Security, LLC (https://www.pumascan.com)
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
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Diagnostics;

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
        public static string GetWorkingDirectory(string assemblyName)
        {
            var workingPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
                , "Microsoft", "VisualStudio", Assembly.GetExecutingAssembly().GetName().Name, ARTIFACTS_DIR, assemblyName);

            if (!Directory.Exists(workingPath))
                Directory.CreateDirectory(workingPath);

            return workingPath;
        }

        public static string GetPumaAppDataPath()
        {
            var filePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
                , "Microsoft", "VisualStudio", Assembly.GetExecutingAssembly().GetName().Name);
		
            if (!Directory.Exists(Path.GetDirectoryName(filePath)))
                Directory.CreateDirectory(Path.GetDirectoryName(filePath));

            return filePath;
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
                if (string.Compare(symbol.ToDisplayString(), baseTypeFullName, StringComparison.Ordinal) == 0)
                    return true;

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
        
        public static IdentifierNameSyntax GetMethodReturnType(MethodDeclarationSyntax syntax)
        {
            IdentifierNameSyntax returnType = null;

            if (syntax?.ReturnType is GenericNameSyntax)
            {
                var generic = syntax?.ReturnType as GenericNameSyntax;
                if (generic.TypeArgumentList.Arguments.Count > 0)
                    returnType = generic.TypeArgumentList.Arguments[0] as IdentifierNameSyntax;
            }

            if (syntax?.ReturnType is IdentifierNameSyntax)
                returnType = syntax?.ReturnType as IdentifierNameSyntax;

            return returnType;
        }

        /// <summary>
        ///     Gets the diagnostic id from the given type's SupportedDiagnosticAttribute attribute data
        /// </summary>
        /// <param name="type"></param>
        /// <returns></returns>
        public static DiagnosticId GetDiagnosticId(Type type)
        {
            var supportedDiagnosticAttribute = type
                .GetCustomAttributes(typeof(SupportedDiagnosticAttribute), true)
                .FirstOrDefault() as SupportedDiagnosticAttribute;

            var diagnosticId = DiagnosticId.None;
            Enum.TryParse(supportedDiagnosticAttribute.Code, out diagnosticId);
            return diagnosticId;
        }

        /// <summary>
        ///     Returns whether node is a descandant of any node of types in type array.
        /// </summary>
        /// <param name="rootNode">The root node. Checks the ancestors of node up to root node</param>
        /// <param name="node">The node to check.</param>
        /// <param name="types">The types to check</param>
        /// <returns></returns>
        public static bool HasAncestorOfType(SyntaxNode rootNode, SyntaxNode node, Type[] types)
        {
            if (types.Contains(node.GetType()))
                return true;

            while (node != rootNode)
            {
                node = node.Parent;
                if (types.Contains(node.GetType()))
                    return true;
            }

            return false;
        }

        /// <summary>
        ///     Returns the first ancestor of given type
        /// </summary>
        /// <param name="rootNode">The ending node.</param>
        /// <param name="node">The starting node.</param>
        /// <param name="type">The type of ancestor to find</param>
        /// <returns></returns>
        public static SyntaxNode GetFirstAncestorOfType(SyntaxNode rootNode, SyntaxNode node, Type type)
        {
            return GetFirstAncestorOfType(rootNode, node, new[] {type});
        }

        public static SyntaxNode GetFirstAncestorOfType(SyntaxNode rootNode, SyntaxNode node, Type[] types)
        {
            if (types.Contains(node.GetType()))
                return node;

            while (node != rootNode)
            {
                node = node.Parent;
                if (types.Contains(node.GetType()))
                    return node;
            }

            return null;
        }

        public static SyntaxNode TrimTrivia(SyntaxNode node)
        {
            return node.WithoutLeadingTrivia().WithoutTrailingTrivia();
        }
    }
}