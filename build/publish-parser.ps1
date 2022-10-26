# publish parser for 2019 package
$FolderName = ".\Puma.Security.Rules\bin\Release\netstandard2.0\tools\parser"
if (!(Test-Path $FolderName)) {    
    Write-Host "Creating parser directory..."
    New-Item -Type Directory $FolderName	
}

Write-Host "Publish parser to directory"
dotnet publish ".\Puma.Security.Parser\Puma.Security.Parser.csproj" -c Release -o $FolderName

Write-Host "Cleanup parser directory"
del "$FolderName\*.pdb"

# publish parser for 2017 package
$FolderName = ".\Puma.Security.Rules.2017\bin\Release\netstandard2.0\tools\parser"
if (!(Test-Path $FolderName)) {    
    Write-Host "Creating parser directory..."
    New-Item -Type Directory $FolderName	
}

Write-Host "Publish parser to directory"
dotnet publish ".\Puma.Security.Parser\Puma.Security.Parser.csproj" -c Release -o $FolderName

Write-Host "Cleanup parser directory"
del "$FolderName\*.pdb"

# publish parser for 2022 package
$FolderName = ".\Puma.Security.Rules.2022\bin\Release\netstandard2.0\tools\parser"
if (!(Test-Path $FolderName)) {    
    Write-Host "Creating parser directory..."
    New-Item -Type Directory $FolderName	
}

Write-Host "Publish parser to directory"
dotnet publish ".\Puma.Security.Parser\Puma.Security.Parser.csproj" -c Release -o $FolderName

Write-Host "Cleanup parser directory"
del "$FolderName\*.pdb"
