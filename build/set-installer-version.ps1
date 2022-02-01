Write-Host "Starting VISX version configuration..."
$BuildVersion = $env:BUILD_VERSION

Write-Host "New installer version $BuildVersion"

# vsixmanifest
$vsixManifestPath = Get-Location | Resolve-Path | Join-Path -ChildPath ".\Puma.Security.Rules.Vsix\source.extension.vsixmanifest"
$content = Get-Content $vsixManifestPath
$xml = New-Object System.Xml.XmlDocument

Write-Host "Reading $vsixManifestPath..."
$xml.LoadXml($content)
$namespace = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
$namespace.AddNamespace("ns", "http://schemas.microsoft.com/developer/vsx-schema/2011")
$node = $xml.SelectSingleNode("//ns:PackageManifest/ns:Metadata/ns:Identity", $namespace)

Write-Host "Setting $vsixManifestPath release attributes..."
$node.SetAttribute("Version", $BuildVersion);

Write-Host "Saving $vsixManifestPath..."
$xml.Save($vsixManifestPath)

# vsixmanifest 2022
$vsixManifestPath = Get-Location | Resolve-Path | Join-Path -ChildPath ".\Puma.Security.Rules.Vsix.VS2022\source.extension.vsixmanifest"
$content = Get-Content $vsixManifestPath
$xml = New-Object System.Xml.XmlDocument

Write-Host "Reading $vsixManifestPath..."
$xml.LoadXml($content)
$namespace = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
$namespace.AddNamespace("ns", "http://schemas.microsoft.com/developer/vsx-schema/2011")
$node = $xml.SelectSingleNode("//ns:PackageManifest/ns:Metadata/ns:Identity", $namespace)

Write-Host "Setting $vsixManifestPath release attributes..."
$node.SetAttribute("Version", $BuildVersion);

Write-Host "Saving $vsixManifestPath..."
$xml.Save($vsixManifestPath)

Write-Host "Finish VSIX installer configuration..."