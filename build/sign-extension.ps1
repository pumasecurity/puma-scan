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

Write-Host "Starting extension signature..."

& $vsixsignPath sign /f "$env:CERTIFICATE_PATH" /p "$env:CERTIFICATE_PASSPHRASE" /v ".\full\PumaSecurity.PumaScanPro.VisualStudio\bin\Release\PumaSecurity.PumaScanPro.VisualStudio.vsix"

Write-Host "Copying end user installer to $env:ARTIFACTS_DIRECTORY\enduser\PumaScanPro_EndUser_$env:BUILD_VERSION.vsix"
New-Item -Type Directory "$env:ARTIFACTS_DIRECTORY\enduser"
Copy-Item -Path ".\full\PumaSecurity.PumaScanPro.VisualStudio\bin\Release\PumaSecurity.PumaScanPro.VisualStudio.vsix" -Destination "$env:ARTIFACTS_DIRECTORY\enduser\PumaScanPro_EndUser_$env:BUILD_VERSION.vsix"
Copy-Item -Path ".\full\PumaSecurity.PumaScanPro.VisualStudio\Publish" -Destination "$env:ARTIFACTS_DIRECTORY\enduser\Publish" -Recurse

Write-Host "Finished extension signature..."