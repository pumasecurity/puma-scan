# Signing is temporarily disabled: the previous code signing certificate expired.
# When signing resumes (planned: Azure Trusted Signing via Sign CLI, since
# Microsoft.VSSDK.VsixSignTool is deprecated), set CERTIFICATE_PATH and
# CERTIFICATE_PASSPHRASE in the pipeline and replace the tool invocation below.
if ([string]::IsNullOrEmpty($env:CERTIFICATE_PATH) -or [string]::IsNullOrEmpty($env:CERTIFICATE_PASSPHRASE)) {
	Write-Host "No signing certificate configured. Skipping VSIX signature (extension will be unsigned)."
	exit 0
}

if ([string]::IsNullOrEmpty($env:BUILD_VERSION)) {
	Write-Host "Error: Version number environment variable is required"
	exit 3
}

if ([string]::IsNullOrEmpty($env:ARTIFACTS_DIRECTORY)) {
	Write-Host "Error: Artifact staging directory not defined"
	exit 3
}

$vsixsignPath = "~\.nuget\packages\microsoft.vssdk.vsixsigntool\16.2.29116.78\tools\vssdk\vsixsigntool.exe"
if (!(Test-Path $vsixsignPath -PathType Leaf)) {
	Write-Host "Error: $vsixsignPath not found"
	exit 4
}

Write-Host "Starting VS2022 extension signature..."

& $vsixsignPath sign /f "$env:CERTIFICATE_PATH" /p "$env:CERTIFICATE_PASSPHRASE" /v ".\Puma.Security.Rules.Vsix.VS2022\bin\Release\Puma.Security.Rules.Vsix.VS2022.vsix"

Write-Host "Finished extension signatures..."
