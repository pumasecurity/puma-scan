if ($env:CERTIFICATE_PATH -eq "") {
	Write-Host "Error: Certificate path environment variable is required."
	exit 1
}

if ($env:CERTIFICATE_PASSPHRASE -eq "") {	
	Write-Host "Error: Certificate passphrase environment variable is required."
	exit 2
}

if ($env:BUILD_VERSION -eq "") {
	Write-Host "Error: Version number environment variable is required"
	exit 3
}

if ($env:ARTIFACTS_DIRECTORY -eq "") {
	Write-Host "Error: Artifact staging directory not defined"
	exit 3
}

$vsixsignPath = "~\.nuget\packages\microsoft.vssdk.vsixsigntool\16.2.29116.78\tools\vssdk\vsixsigntool.exe"
if (!(Test-Path $vsixsignPath -PathType Leaf)) {
	Write-Host "Error: $vsixsignPath not found"
	exit 4
}

Write-Host "Starting VS2017 extension signature..."

& $vsixsignPath sign /f "$env:CERTIFICATE_PATH" /p "$env:CERTIFICATE_PASSPHRASE" /v ".\Puma.Security.Rules.Vsix.VS2017\bin\Release\Puma.Security.Rules.Vsix.VS2017.vsix"

Write-Host "Starting VS2019 extension signature..."

& $vsixsignPath sign /f "$env:CERTIFICATE_PATH" /p "$env:CERTIFICATE_PASSPHRASE" /v ".\Puma.Security.Rules.Vsix\bin\Release\Puma.Security.Rules.Vsix.vsix"

Write-Host "Starting VS2022 extension signature..."

& $vsixsignPath sign /f "$env:CERTIFICATE_PATH" /p "$env:CERTIFICATE_PASSPHRASE" /v ".\Puma.Security.Rules.Vsix.VS2022\bin\Release\Puma.Security.Rules.Vsix.VS2022.vsix"

Write-Host "Finished extension signatures..."