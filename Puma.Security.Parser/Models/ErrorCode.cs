using System;
using System.Collections.Generic;
using System.Text;

namespace Puma.Security.Parser.Models
{
    internal enum ErrorCode : int
    {
        Success = 0,
        ErrorThreshold = 1,

        InvalidArguments = 1000,
        Exception = 1001,
    }
}
