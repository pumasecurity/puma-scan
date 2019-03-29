# Puma Scan CLI Parsing Tool

The Puma.Security.Parser utility to parse MSBuild results and export the Puma Scan findings to alternative data formats. 

## Prerequisites

.NET Core 2.1 must be installed on the machine running the parser.

## Command

Run the following command to parse MSBuild results and filter down to Puma Scan warnings

```
dotnet "C:\Tools\Puma.Security.Parser\Puma.Security.Parser.dll" --file "%WORKSPACE%\build_warnings.log" --workspace "%WORKSPACE%" --output puma_warnings.log
```