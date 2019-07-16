<# 
    .Synopsis 
        ---- Publish Layered Image from ELM to Datastore ----
        Run on management server CTXAL Module Installed
    .Description 
        ---- Publish Layered Image from ELM ----
        '-Inputpath' can be used to select the latest image revision to publish based on the reference names in the inputfile
        CAL_PowerShell_SDK_Define_Images2Process.ps1 is used to build the Images4$Environment.csv file, where $Environment references DTA or PROD
    .Example 
        CAL_PowerShell_SDK_Publish_Image -Environment DTA -Credential $Credential [-Inputpath \\nac.ppg.com\dfs\Citrix\Sources\XD\Scripts\Images2Process]
    .Notes
        Author: Siebrand Feenstra - s.feenstra@loginconsultants.nl
#>

[cmdletbinding(SupportsShouldProcess=$True)]

param(
[parameter(Mandatory=$true)]
[ValidateSet("DTA", "DEV", "ACC", "PROD")]
$Environment,
[parameter(Mandatory=$false)]
$Inputpath, # provide the path to the Images4$Environment.csv file containing the references names for the images to export
[ValidateNotNull()]
[System.Management.Automation.PSCredential]
[System.Management.Automation.Credential()]
$Credential = [System.Management.Automation.PSCredential]::Empty
)

# Define error action preference
$ErrorActionPreference = "Continue"

# Variables
$Skiplast = "3"
$DTAApliance = "agofxdelmd01.nac.ppg.com"
$PRODAppliance = "agofxdelm01.nac.ppg.com"
$imagetopublish = @()
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# LOGGING and FUNCTIONS
$logpath = "loguncpathhere"
if (!(test-path $logpath)){try{New-Item -ItemType directory -Path $loglocation -Force}catch [Exception]{Write-warning $_.Exception.Message}}
$LogFile = "CAL_PowerShell_SDK_Publish_Image.log"
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
Logaction "--- CAL_PowerShell_SDK_Publish_Image ---"

# MODULES -----------------------
Import-Module "$(Get-ScriptDirectory)\LIC_Function_Library.psm1" -DisableNameChecking

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

# Inputfolder / File including reference names for the image to select for processing
if ($Inputpath)
{
    $Inputpath = $($Inputpath -replace '[\\/]+$')
    if ((test-path -Path "$Inputpath\Images4$Environment.json" -ea 0) -eq $true)
    {            
        $inputfile = $("$Inputpath\Images4$Environment.json")
        Write-Host "$(Write-TimeNumberSign) Inputfile provided [$inputfile]" -ForegroundColor Cyan
    }
    else {$inputfile = $null}
}

# Connect to the DEV Appliance
if ($Environment -eq "DTA"){$apdevlip = $DTAApliance}
elseif ($Environment -eq "DEV"){$apdevlip = $PRODAppliance}
elseif ($Environment -eq "ACC"){$apdevlip = $PRODAppliance}
elseif ($Environment -eq "PROD"){$apdevlip = $PRODAppliance}

Write-Host "$(Write-TimeNumberSign) Selected Applicance: [$($apdevlip.ToUpper())]" -ForegroundColor Yellow
Logaction "Selected Applicance: [$($apdevlip.ToUpper())]"
$ALWebSession = Connect-alsession -aplip $apdevlip -Credential $Credential
function Get-ScriptDirectory {
    if ($psise) {Split-Path $psise.CurrentFile.FullPath}
    else {Split-Path $script:MyInvocation.MyCommand.Path}
}

### Script ####

# If inputpath is provided read reference names from "$Inputpath\Images4$Environment.csv" otherwise
# Select image in gridview, multi select is possible

if ($inputfile -ne $null)
{
    # Copy item to have a file backup
    copy-item -Path $inputfile -Destination "$Inputpath\Copy" -Force | out-null
    
    # Read inputfile json to retrieve reference names. this file can be build with Infra_Define_Images2Process.ps1
    try {$Images2Process = Get-Content $inputfile -ea Stop -Raw | ConvertFrom-Json
        } catch [Exception] {Write-Host "$(Write-TimeNumberSign) $_" -ForegroundColor RED}

    $Images = @()
    $FinalResult = @()

    if ($Images2Process){
        foreach ($Image2Process in $Images2Process)
        {
            $Images += Get-ALImageComp -websession $ALWebSession | Where-Object {$_.name -match "$($Image2Process.ImageReference)"} | Sort-Object Name -Descending | Select-Object -First 1
            $FinalResult += New-Object psobject -Property @{
                ImageReference = $Image2Process.ImageReference
                Catalog = $Image2Process.Catalog
                StorageResource = $Image2Process.StorageResource
                id = (Get-ALImageComp -websession $ALWebSession | Where-Object {$_.name -match "$($Image2Process.ImageReference)"} | Sort-Object Name -Descending | Select-Object -First 1).id
                ImageName = (Get-ALImageComp -websession $ALWebSession | Where-Object {$_.name -match "$($Image2Process.ImageReference)"} | Sort-Object Name -Descending | Select-Object -First 1).Name
                }
        }

        # When inputfile contains multiple equal ImageReferences for different catalogs select only the ones being unique
        $Images = $Images | Sort-Object Name -Unique
        
        # Overwrite $Inputfile in json format
        $FinalResult | ConvertTo-Json -Depth 5 | Out-File $inputfile

    }
    else
    {
        Write-Host "$(Write-TimeNumberSign) [$inputfile] is Empty" -ForegroundColor RED
        Break
    }
} 
else
{
    Write-Host "$(Write-TimeNumberSign) Select Image(s)" -ForegroundColor Cyan
    $Images = Get-ALImageComp -websession $ALWebSession | Where-Object {$_.name -match "[SR]_[W]\d{2}_[A-Z]{3,5}_(IMG)_[R]\d{3}"} | Sort-Object DateLastModified -Descending | Out-GridView -PassThru
}

if ($Images -eq $null){
Write-Host "$(Write-TimeNumberSign) No Image selected. EXITING" -ForegroundColor Red
break
}

foreach ($image in $Images | Sort-Object Name -Unique){

    Write-Host "$(Write-TimeNumberSign) Image to Publish : [$($image.name)] - [$([array]::indexof($Images.id,$image.id) +1)/$($Images.id.Count)]" -ForegroundColor Cyan
    Logaction "Image to Publish : [$($image.name)] - [$([array]::indexof($Images.id,$image.id) +1)/$($Images.id.count)]"

    # Build array of images to be published
    $imagetopublish += Get-ALImage -websession $ALWebSession | Where-Object {$_.name -eq $($image.Name)}
}

$imagetopublish | % {Write-Host "$(Write-Timeindent ) publishing image [$($_.name)] with id: [$($_.id)]" -ForegroundColor yellow}
$imagetopublish | % {Logaction "publishing image [$($_.name)] with id: [$($_.id)]"}    

# Publish the images
invoke-alpublish -websession $ALWebSession -imageid $imagetopublish.id -Outvariable invokealpublish -Confirm:$false | Out-Null
                    
# Get-Status and loop while task status is running
$invokealpublishStatus = Get-ALStatus -id $invokealpublish -websession $ALWebSession

    $a = 0
    Do {
    IF ($a -eq "99") {$a=0}
    if (($invokealpublishStatus.Status -notlike "Running") -and ($invokealpublishStatus.Status -notlike "Pending")){
        $a=100
        Write-Progress -Activity "Publishing image [$(($imagetopublish.name -join (' | ')))] done " -PercentComplete $a -Status "Finish."
        Start-Sleep 1
        Write-Progress "Done" "Done" -completed	
        break
    } ELSE {
        $invokealpublishStatus = Get-ALStatus -id $invokealpublish -websession $ALWebSession
        $a++
        Write-Progress -Activity "Publishing image [$(($imagetopublish.name -join (' | ')))] running, waiting until finished..." -PercentComplete $a -Status "Please wait..."
        start-sleep 5
        }
    } While ($a -ne 100)

Write-Host "$(Write-TimeIndent) Export for [$(($imagetopublish.name -join (' | ')))] FINISHED" -ForegroundColor Green
Logaction "Export for [$(($imagetopublish.name -join (' | ')))] FINISHED"

