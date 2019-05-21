<# 
    .Synopsis 
        --- Removes Image revisions other than the last three ---
    .Description 
        Retrieve all revisions available for Unique Image names, and delete the ones older than the latest three revisions.
    .Example 
        CAL_PowerShell_SDK_Cleanup_Obsolete_Images_DTA_V1.0.ps1
#>

[cmdletbinding(SupportsShouldProcess=$True)]

param(
# The LayerType to process, either OSLayer or Applayer.
[parameter(Mandatory=$false)]
[ValidateSet("DTA", "PROD")]
$Environment = "DTA",
[ValidateNotNull()]
[System.Management.Automation.PSCredential]
[System.Management.Automation.Credential()]
$Credential = [System.Management.Automation.PSCredential]::Empty
)  

# Define error action preference
$ErrorActionPreference = "Continue"

# Variables
$Skiplast = "3"
if ($Environment -eq "DTA"){$apdevlip = "yourdevapplianceunchere"}
elseif ($Environment -eq "PROD"){$apdevlip = "yourdevapplianceunchere"}

# LOGGING and FUNCTIONS
$logpath = "\\nac.ppg.com\dfs\Citrix\Sources\XD\Scripts\Logs"
if (!(test-path $logpath)){try{New-Item -ItemType directory -Path $loglocation -Force}catch [Exception]{Write-warning $_.Exception.Message}}
$LogFile = "CAL_PowerShell_SDK_Cleanup_Obsolete_Images.log"
$LogFileName = $logpath + "\$LogFile"
Function LogAction
	{
	Param([string]$i)
	[string]$LogDate = $(get-date -uformat "%d-%m-%Y | %H:%M:%S.%ms") + " |"
	Add-Content -path $LogFileName -value "$LogDate $i"
    }

function Get-ScriptDirectory {
    if ($psise) {Split-Path $psise.CurrentFile.FullPath}
    else {Split-Path $script:MyInvocation.MyCommand.Path}
}

# Logging
Logaction "--- CAL_PowerShell_SDK_Cleanup_Obsolete_Images ---"

# MODULES -----------------------
Import-Module "$(Get-ScriptDirectory)\LIC_Function_Library.psm1" -DisableNameChecking
# Update-Module -Name ctxal-sdk

# Verify credentials
if ($Credential -ne [System.Management.Automation.PSCredential]::Empty)
{
    
    if ((Test-ADCredential -Credential $Credential) -eq $false)
    {
        [int]$Credtestcount = '1'
        DO 
        {
            Write-Host "$(Write-TimeNumberSign) Credential incorrect [$Credtestcount/3]" -ForegroundColor Red
            Logaction "Credential incorrect [$Credtestcount/3]"
            $Credential = $host.ui.PromptForCredential("Connecting CAL appliance", "Please enter your user name and password to access the CAL appliance.","", "")
            $Credtestcount += '1'
        
        } until ((Test-ADCredential -Credential $Credential) -eq $true -or $Credtestcount -gt '3')

        Write-Host "$(Write-TimeNumberSign) credentials provided incorrectly 3 times. EXITING" -ForegroundColor Red
        Logaction "credentials provided incorrectly 3 times. EXITING"
        break 
    } 
    
    if ((Test-ADCredential -Credential $Credential) -eq $true){
        Write-Host "$(Write-TimeNumberSign) Credential verified" -ForegroundColor Green
        Logaction "Credential verified"
    }

} else {
        
    Write-Host "$(Write-TimeNumberSign) No credentials provided. EXITING" -ForegroundColor Red
    Logaction "No credentials provided. EXITING"
    break 
}

# Connect to the DEV Appliance
Write-Host "$(Write-TimeNumberSign) Selected Applicance: [$($apdevlip.ToUpper())]" -ForegroundColor Yellow
Logaction "Selected Applicance: [$($apdevlip.ToUpper())]"
$ALWebSession = Connect-alsession -aplip $apdevlip -Credential $Credential

function Get-ScriptDirectory {
    if ($psise) {Split-Path $psise.CurrentFile.FullPath}
    else {Split-Path $script:MyInvocation.MyCommand.Path}
}

### Script ####

#Get Image Composition
$ImagesDEV = Get-ALImageComp -websession $ALWebSession

if ($ImagesDEV -eq $null){
Write-Host "$(Write-TimeNumberSign) No Image selected. EXITING" -ForegroundColor Red
break
}

Write-Host "$(Write-TimeIndent) Retrieve matching image names" -ForegroundColor Yellow
Logaction "Retrieve matching image names"
$my_match_list = @($imagesdev.Name -match "[SR]_[W]\d{2}_[A-Z]{3,5}_(IMG)_[R]\d{3}" | ForEach-Object {$_.Substring(0, $_.LastIndexOf("R"))} | Select-Object -Unique)
$my_strings_list = @($imagesdev.Name -match "[SR]_[W]\d{2}_[A-Z]{3,5}_(IMG)_[R]\d{3}")

foreach($i in $my_match_list){
Write-Host "$(Write-TimeIndent) matching item: $i" -ForegroundColor Yellow
Logaction "matching item: $i"

# ($my_matchList[0]|$Mymatchlist[1]|...)
[regex]$Match_regex = ‘(‘ + (($i | ForEach-Object {[regex]::escape($_)}) –join “|”) + ‘)’

# Get matching items based on the match item in the list of images and select any other that the last 3
$Selection = $my_strings_list -match $Match_regex | Sort-Object | Select-Object -SkipLast $Skiplast
if ($Selection -eq $null)
{
    Write-Host "$(Write-TimeIndent) Nothing to do for matching item: $i" -ForegroundColor Green
    Logaction "Nothing to do for matching item: $i"
    Continue
}

    Write-Host "$(Write-TimeIndent) The following Image revisions are candidates to be removed: [$($Selection -join ('|'))]" -ForegroundColor Yellow
    Logaction "The following Image revisions are candidates to be removed: [$($Selection -join ('|'))]"

    foreach ($Image in $Selection)
    {
        $Imagetobremoved = $imagesdev | Where-Object {$_.name -eq $image}
        Write-Host "$(Write-TimeIndent) Process Image [$($Imagetobremoved.Name)] with id [$($Imagetobremoved.id)])" -ForegroundColor Yellow
        Logaction "Process Image [$($Imagetobremoved.Name)] with id [$($Imagetobremoved.id)])"

        Try {
            Remove-ALImage -websession $ALWebSession -id $($Imagetobremoved.id) -Confirm:$false
            Write-Host "$(Write-TimeIndent) Succesfully Removed Image [$($Imagetobremoved.Name)] with id [$($Imagetobremoved.id)])" -ForegroundColor Green
            Logaction "Succesfully Removed Image [$($Imagetobremoved.Name)] with id [$($Imagetobremoved.id)])"
            } Catch [Exception] {Write-Error "Remove-ALImage - $_"}
        }
    }

# DisConnect from Appliances
disconnect-alsession -websession $ALWebSession
###
Write-Host "$(Write-TimeNumberSign) *** READY ***" -ForegroundColor Green
Logaction "*** READY ***"