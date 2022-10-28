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

namespace Puma.Security.Parser
{
    public static class RegexConstants
    {
        public const string _REGEX_PUMA_CATEGORY = @"(warning) (SEC)[\d]+:";
        public const string _REGEX_PUMA_ERROR_CODE = @"(SEC)[\d]+";
        public const string _REGEX_RULE_SEVERITY = @"([^\s]+)";
        public const string _REGEX_FULL_WIN_FILE_PATH = @"\b[A-Z]:\\(?:[^\\/:*?""<>|\x00-\x1F]+\\)*[^\\/:*?""<>|\x00-\x1F\]]*";
        public const string _REGEX_WIN_DIRECTORY = @"([A-Z]:|\\\\[a-z0-9 %._-]+\\[a-z0-9 $%._-]+)?(\\?(?:[^\\/:*?""<>|\x00-\x1F]+\\)+)";
        public const string _REGEX_VS_RELATIVE_PATH = @"([^\\/:*?""<>|\x00-\x1F]+\\)*[^\\/:*?""<>|\x00-\x1F]+\(\d+,\d+\)";
        public const string _REGEX_WARNING_DELIMITER = @":\ \[?";
        public const char _VS_PATH_DELIMETER_OPEN = '(';
        public const char _VS_PATH_DELIMETER_CLOSE = ')';
        public const char _VS_LOCATION_DELIMETER = ',';
        public const char _VS_PROJECT_DELIMETER_OPEN = '[';
        public const char _VS_PROJECT_DELIMETER_CLOSE = ']';
        public const string _MS_BUILD_WARNING_FORMAT = @"{0}({1},{2}): warning {3}: {4} [{5}]";
        public const string _REGEX_ADDITIONAL_FILES_PATH = @" [A-Za-z]:\\[A-Za-z0-9 %\._-]+";
        public const string _REGEX_ADDITIONAL_FILES_METADATA = @" \{0\}(\{1\}): \{2\}";
    }
}