## Executing Tests

This project uses .NET Core XUNIT for unit testing. To execute the unit tests, run a command similar to the following:

```
dotnet restore
dotnet xunit -namespace <FULL PATH TO METHOD>

e.g.
dotnet xunit -namespace Microsoft.Web.XmlTransform.Test
```