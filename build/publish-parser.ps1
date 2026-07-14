# publish parser into the analyzer package tools folder
$FolderName = ".\Puma.Security.Rules\bin\Release\netstandard2.0\tools\parser"
if (!(Test-Path $FolderName)) {
    Write-Host "Creating parser directory..."
    New-Item -Type Directory $FolderName
}

Write-Host "Publish parser to directory"
dotnet publish ".\Puma.Security.Parser\Puma.Security.Parser.csproj" -c Release -o $FolderName

Write-Host "Cleanup parser directory"
del "$FolderName\*.pdb"
