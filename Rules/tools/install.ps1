param($installPath, $toolsPath, $package, $project)

$analyzersPaths = Join-Path (Join-Path (Split-Path -Path $toolsPath -Parent) "analyzers" ) * -Resolve

foreach($analyzersPath in $analyzersPaths)
{
    # Install the language agnostic analyzers.
    if (Test-Path $analyzersPath)
    {
        foreach ($analyzerFilePath in Get-ChildItem $analyzersPath -Filter *.dll)
        {
            if($project.Object.AnalyzerReferences)
            {
                $project.Object.AnalyzerReferences.Add($analyzerFilePath.FullName)
            }
        }
    }
}

# $project.Type gives the language name like (C# or VB.NET)
$languageFolder = ""
if($project.Type -eq "C#")
{
    $languageFolder = "cs"
}
if($project.Type -eq "VB.NET")
{
    $languageFolder = "vb"
}
if($languageFolder -eq "")
{
    return
}

foreach($analyzersPath in $analyzersPaths)
{
    # Install language specific analyzers.
    $languageAnalyzersPath = join-path $analyzersPath $languageFolder
    if (Test-Path $languageAnalyzersPath)
    {
        foreach ($analyzerFilePath in Get-ChildItem $languageAnalyzersPath -Filter *.dll)
        {
            if($project.Object.AnalyzerReferences)
            {
                $project.Object.AnalyzerReferences.Add($analyzerFilePath.FullName)
            }
        }
    }
}

#$xml = [xml] (get-content $project.FullName)
#$ns = @{msb = 'http://schemas.microsoft.com/developer/msbuild/2003'}
#$add = $xml | Select-Xml "//msb:PropertyGroup/msb:AdditionalFileItemNames" -Namespace $ns

#if(!$add) {
#	$propertyGroup = $xml | Select-Xml "//msb:PropertyGroup/msb:AssemblyName/.." -Namespace $ns
#	$newAdd = $xml.CreateElement("AdditionalFileItemNames", 'http://schemas.microsoft.com/developer/msbuild/2003')
#	$newAdd.InnerText = '$(AdditionalFileItemNames);Content'
#	$propertyGroup.Node.AppendChild($newAdd)
#	$xml.Save($project.FullName)
#}

#if($add) {
#	$containsContent = $add.Node.InnerText -like '*Content*'
#	if (!$containsContent) { 
#		$add.Node.InnerText = $add.Node.InnerText + ';Content'
#		$xml.Save($project.FullName)
#	}
#}