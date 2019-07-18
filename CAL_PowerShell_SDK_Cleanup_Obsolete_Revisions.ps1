<# 
    .Synopsis 
        Cleanup the two (by default) last layer revisions based on type (OS, App and Platform) name and ‘revision number’ not being assigned.
    .Example 
        CAL_PowerShell_SDK_Cleanup_Obsolete_Revisions.ps1 [-LayerType {OSLayer|AppLayer|PlatformLayer}] [-Environment {DTA|PROD}] [-Credential <pscredential>]
    .Notes
        Author: Siebrand Feenstra - s.feenstra@loginconsultants.nl
#>

[cmdletbinding(SupportsShouldProcess=$True)]

param(
# The LayerType to process, either OSLayer, PlatFormLayer or Applayer.
[parameter(Mandatory=$true)]
[ValidateSet("OSLayer", "PlatFormLayer",  "AppLayer")]
$LayerType,
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
$Skiplast = "2"
$DTAApliance = "DTAAppliancehere"
$PRODAppliance = "PRODAppliancehere"
$logpath = "loguncpathhere"

# LOGGING and FUNCTIONS
if (!(test-path $logpath)){try{New-Item -ItemType directory -Path $loglocation -Force}catch [Exception]{Write-warning $_.Exception.Message}}
$LogFile = "CAL_PowerShell_SDK_Cleanup_Obsolete_Revisions.log"
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
Logaction "--- CAL_PowerShell_SDK_Cleanup_Obsolete_Revisions ---"

# MODULES -----------------------
Import-Module "$(Get-ScriptDirectory)\LIC_Function_Library.psm1" -DisableNameChecking
# install-Module -Name ctxal-sdk -Verbose -Scope AllUsers
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

# Connect to the Appliance
if ($Environment -eq "DTA"){$apdevlip = $DTAApliance}
elseif ($Environment -eq "PROD"){$apdevlip = $PRODAppliance}
Write-Host "$(Write-TimeNumberSign) Selected Applicance: [$($apdevlip.ToUpper())]" -ForegroundColor Yellow
Logaction "Selected Applicance: [$($apdevlip.ToUpper())]"
$ALWebSession = Connect-alsession -aplip $apdevlip -Credential $Credential 

# Get Fileshare details from the appliance
$fileshare = Get-ALRemoteshare -websession $ALWebSession
if ($fileshare -eq $null)
{
    Write-Error "$(Write-TimeIndent) Fileshare could not be determined. EXITING..."
    Logaction "Fileshare could not be determined. EXITING..."
    Break
}

### Script ####

if ($LayerType -eq "AppLayer"){
Write-Host "$(Write-TimeIndent) Layer to process is of type: $LayerType" -ForegroundColor Yellow
Logaction "Layer to process is of type: $LayerType"

    # Get teh layers for the given layertype
    Write-Host "$(Write-TimeIndent) Retrieve all Layers of type: $LayerType" -ForegroundColor Yellow
    Logaction "Retrieve all Layers of type: $LayerType"
    $ALAppLayers = Get-ALAppLayer -websession $ALWebSession
 
    Foreach ($ALAppLayer in $ALAppLayers){
            
        # Get ID of latest App layer revision
        Write-Host "$(Write-TimeIndent) Process layer [$($ALAppLayer.Name)]" -ForegroundColor Cyan
        Logaction "Process layer [$($ALAppLayer.Name)]"
        $ALAppLayerRevisions = Get-ALAppLayerDetail -websession $ALWebSession -id $ALAppLayer.Id
        $ALAppLayerLatestRevision = $ALAppLayerRevisions.Revisions.AppLayerRevisionDetail | Where-Object {$_.State -eq "Deployable"} | Sort-Object DisplayedVersion -Descending | Select-Object -First 1
        Write-Host "$(Write-TimeIndent) Most recent layer revision for [$($ALAppLayer.Name)] is [$($ALAppLayerLatestRevision.DisplayedVersion)]" -ForegroundColor Yellow
        Logaction "Most recent layer revision for [$($ALAppLayer.Name)] is [$($ALAppLayerLatestRevision.DisplayedVersion)]"
    
        # Retrieve all but the last two layerrevisions which can be deleted and being older than than the most recent assigned revision
        $AllAppLayerRevsCanDelete = $ALAppLayerRevisions.Revisions.AppLayerRevisionDetail | Where-Object {$_.Candelete -eq $True -and ($_.DisplayedVersion -lt $ALAppLayerLatestRevision.DisplayedVersion)} | Sort-Object DisplayedVersion | Select-Object -SkipLast $Skiplast
        if ($AllAppLayerRevsCanDelete -eq $null){
            Write-Host "$(Write-TimeIndent) No obsolete layer revisions available for layer: [$($ALAppLayer.Name)], Continue" -ForegroundColor Yellow
            Logaction "No obsolete layer revisions available for layer: [$($ALAppLayer.Name)], Continue"
            Continue
        }

        Write-Host "$(Write-TimeIndent) The following layer revisions are candidates to be removed: [$($AllAppLayerRevsCanDelete.DisplayedVersion -join ('|'))]" -ForegroundColor Yellow
        Logaction "The following layer revisions are candidates to be removed: [$($AllAppLayerRevsCanDelete.DisplayedVersion -join ('|'))]"

        foreach ($AppLayerRevCanDelete in $AllAppLayerRevsCanDelete){
            Write-Host "$(Write-TimeIndent) Process Layer Revision [$($AppLayerRevCanDelete.DisplayedVersion)] with id [$($AppLayerRevCanDelete.id)])" -ForegroundColor Yellow
            Logaction "Process Layer Revision [$($AppLayerRevCanDelete.DisplayedVersion)] with id [$($AppLayerRevCanDelete.id)])"
            
            Try 
            {
                Remove-ALAppLayerRev -websession $ALWebSession -appid $AppLayerRevCanDelete.Layerid -apprevid $AppLayerRevCanDelete.id -fileshareid $fileshare.id -OutVariable AppLayerRevDeleted -Confirm:$false | Out-Null
            }   Catch [Exception] 
            {
                Write-Error "$(Write-TimeIndent) Remove-ALAppLayerRev - $_"
                Logaction "Remove-ALAppLayerRev - $_"
            }
                   
                # Get-Status and loop while task status is running
                $DeleteRevStatus = Get-ALStatus -id $AppLayerRevDeleted.WorkTicketId -websession $ALWebSession
                
                $a = 0
                Do {
                    IF ($a -eq "99") {$a=0}
                    if (($DeleteRevStatus.Status -notlike "Running") -and ($DeleteRevStatus.Status -notlike "Pending")){
                        $a=100
		                Write-Progress -Activity "Deleting Layer Revision is ready..." -PercentComplete $a -Status "Finish."
		                Start-Sleep 2
                        Write-Progress "Done" "Done" -completed
		                break
	                } ELSE {
                        $DeleteRevStatus = Get-ALStatus -id $AppLayerRevDeleted.WorkTicketId -websession $ALWebSession | Out-Null
                        $a++
		                Write-Progress -Activity "Creating new layer revision is in [$($DeleteRevStatus.Status)] state, waiting until finished..." -PercentComplete $a -Status "Please wait..."
		                Start-Sleep 0.5
                        }
                    } While ($a -ne 100)

                    Start-sleep 5

                # Verify if layer revisions has been deleted
                if ((Get-ALAppLayerDetail -websession $ALWebSession -id $ALAppLayer.Id).Revisions.AppLayerRevisionDetail | Where-Object {$_.id -eq $AppLayerRevCanDelete.id} -eq $null)
                {
                    Write-Host "$(Write-TimeIndent) Successfull removed revision for layer: [$($ALAppLayer.Name)] with version: [$($AppLayerRevCanDelete.DisplayedVersion)] and id [$($AppLayerRevCanDelete.id)])" -ForegroundColor Green
                    LogAction "Successfull removed revision for layer: [$($ALAppLayer.Name)] with version: [$($AppLayerRevCanDelete.DisplayedVersion)] and id [$($AppLayerRevCanDelete.id)])"
                } 
                Else 
                {
                    Write-Error "$(Write-TimeIndent) Removal of revision for layer: [$($ALAppLayer.Name)] with version: [$($AppLayerRevCanDelete.DisplayedVersion)] and id [$($AppLayerRevCanDelete.id)]) FAILED - $_"
                    LogAction "Removal of revision for layer: [$($ALAppLayer.Name)] with version: [$($AppLayerRevCanDelete.DisplayedVersion)] and id [$($AppLayerRevCanDelete.id)]) FAILED - $_"
                }
        }
    }
}

if ($LayerType -eq "OsLayer"){
Write-Host "$(Write-TimeIndent) Layer to process is of type: $LayerType" -ForegroundColor Yellow
Logaction "$(Write-TimeIndent) Layer to process is of type: $LayerType"

    # Get ID of latest layer revision    
    Write-Host "$(Write-TimeIndent) Retrieve all Layers of type: $LayerType" -ForegroundColor Yellow
    Logaction "Retrieve all Layers of type: $LayerType"
    $ALOsLayers = Get-ALOsLayer -websession $ALWebSession
 
    Foreach ($ALOsLayer in $ALOsLayers){
            
        # Get ID of latest Os layer revision
        Write-Host "$(Write-TimeIndent) Process layer [$($ALOsLayer.Name)]" -ForegroundColor Cyan
        Logaction "Process layer [$($ALOsLayer.Name)]"
        $ALOsLayerRevisions = Get-ALOsLayerDetail -websession $ALWebSession -id $ALOsLayer.Id
        $ALOsLayerLatestRevision = $ALOsLayerRevisions.Revisions.OsLayerRevisionDetail | Where-Object {($_.State -eq "Deployable") -and ($_.DisplayedVersion -notmatch "1803R") -and ($_.DisplayedVersion -notmatch "1809")} | Sort-Object DisplayedVersion -Descending | Select-Object -First 1
        Write-Host "$(Write-TimeIndent) Most recent layer revision for [$($ALOsLayer.Name)] is [$($ALOsLayerLatestRevision.DisplayedVersion)]" -ForegroundColor Yellow
        Logaction "Most recent layer revision for [$($ALOsLayer.Name)] is [$($ALOsLayerLatestRevision.DisplayedVersion)]"
    
        # Retrieve all but the last two layerrevisions which can be deleted and being older than than the most recent assigned revision
        $AllOsLayerRevsCanDelete = $ALOsLayerRevisions.Revisions.OsLayerRevisionDetail | Where-Object {$_.Candelete -eq $True -and ($_.DisplayedVersion -lt $ALOsLayerLatestRevision.DisplayedVersion) -and ($_.DisplayedVersion -notmatch "1803R")} | Sort-Object DisplayedVersion | Select-Object -SkipLast 2
        if ($AllOsLayerRevsCanDelete -eq $null){
            Write-Host "$(Write-TimeIndent) No obsolete layer revisionsavailable for layer: [$($ALOsLayer.Name)], Continue" -ForegroundColor Yellow
            Logaction "No obsolete layer revisions available for layer: [$($ALOsLayer.Name)], Continue"
            Continue
        }

        Write-Host "$(Write-TimeIndent) The following layer revisions are candidates to be removed: [$($AllOsLayerRevsCanDelete.DisplayedVersion -join ('|'))]" -ForegroundColor Yellow
        Logaction "The following layer revisions are candidates to be removed: [$($AllOsLayerRevsCanDelete.DisplayedVersion -join ('|'))]"

        foreach ($OsLayerRevCanDelete in $AllOsLayerRevsCanDelete){
            Write-Host "$(Write-TimeIndent) Process Layer Revision [$($OsLayerRevCanDelete.DisplayedVersion)] with id [$($OsLayerRevCanDelete.id)])" -ForegroundColor Yellow
            Logaction "Process Layer Revision [$($OsLayerRevCanDelete.DisplayedVersion)] with id [$($OsLayerRevCanDelete.id)])"

            Try 
            {
                Remove-ALOsLayerRev -websession $ALWebSession -Osid $OsLayerRevCanDelete.Layerid -Osrevid $OsLayerRevCanDelete.id -fileshareid $fileshare.id -OutVariable OsLayerRevDeleted -Confirm:$false | Out-Null
            }   Catch [Exception] 
            {
                Write-Error "$(Write-TimeIndent) Remove-ALOsLayerRev - $_"
                Logaction "Remove-ALAppLayerRev - $_"
            }
                    
                # Get-Status and loop while task status is running
                $DeleteRevStatus = Get-ALStatus -id $OsLayerRevDeleted.WorkTicketId -websession $ALWebSession
                
                $a = 0
                Do {
                    IF ($a -eq "99") {$a=0}
                    if (($DeleteRevStatus.Status -notlike "Running") -and ($DeleteRevStatus.Status -notlike "Pending")){
                        $a=100
		                Write-Progress -Activity "Deleting Layer Revision is ready..." -PercentComplete $a -Status "Finish."
		                Start-Sleep 2
                        Write-Progress "Done" "Done" -completed	
		                break
	                } ELSE {
                        $DeleteRevStatus = Get-ALStatus -id $OsLayerRevDeleted.WorkTicketId -websession $ALWebSession | Out-Null
                        $a++
		                Write-Progress -Activity "Creating new layer revision is in [$($DeleteRevStatus.Status)] state, waiting until finished..." -PercentComplete $a -Status "Please wait..."
		                Start-Sleep 0.5
                        }
                    } While ($a -ne 100)

                # Verify if layer revisions has been deleted
                if ((Get-ALOsLayerDetail -websession $ALWebSession -id $ALOsLayer.Id).Revisions.OsLayerRevisionDetail | Where-Object {$_.id -eq $OsLayerRevCanDelete.id} -eq $null)
                {
                    Write-Host "$(Write-TimeIndent) Successfull removed revision for layer: [$($ALOsLayer.Name)] with version: [$($OsLayerRevCanDelete.DisplayedVersion)] and id [$($OsLayerRevCanDelete.id)])" -ForegroundColor Green
                    LogAction "Successfull removed revision for layer: [$($ALOsLayer.Name)] with version: [$($OsLayerRevCanDelete.DisplayedVersion)] and id [$($OsLayerRevCanDelete.id)])"
                } 
                Else 
                {
                    Write-Error "$(Write-TimeIndent) Removal of revision for layer: [$($ALOsLayer.Name)] with version: [$($OsLayerRevCanDelete.DisplayedVersion)] and id [$($OsLayerRevCanDelete.id)]) FAILED - $_"
                    LogAction "Removal of revision for layer: [$($ALOsLayer.Name)] with version: [$($OsLayerRevCanDelete.DisplayedVersion)] and id [$($OsLayerRevCanDelete.id)]) FAILED - $_"
                }
        }
    }
}

if ($LayerType -eq "PlatformLayer"){
Write-Host "$(Write-TimeIndent) Layer to process is of type: $LayerType" -ForegroundColor Yellow
Logaction "$(Write-TimeIndent) Layer to process is of type: $LayerType"

    # Get ID of latest layer revision    
    Write-Host "$(Write-TimeIndent) Retrieve all Layers of type: $LayerType" -ForegroundColor Yellow
    Logaction "Retrieve all Layers of type: $LayerType"
    $ALPlatformLayers = Get-ALPlatformLayer -websession $ALWebSession
 
    Foreach ($ALPlatformLayer in $ALPlatformLayers){
            
        # Get ID of latest Platform layer revision
        Write-Host "$(Write-TimeIndent) Process layer [$($ALPlatformLayer.Name)]" -ForegroundColor Cyan
        Logaction "Process layer [$($ALPlatformLayer.Name)]"
        $ALPlatformLayerRevisions = Get-ALPlatformLayerDetail -websession $ALWebSession -id $ALPlatformLayer.Id
        $ALPlatformLayerLatestRevision = $ALPlatformLayerRevisions.Revisions.PlatformLayerRevisionDetail | Where-Object {$_.State -eq "Deployable"} | Sort-Object DisplayedVersion -Descending | Select-Object -First 1
        Write-Host "$(Write-TimeIndent) MPlatformt recent layer revision for [$($ALPlatformLayer.Name)] is [$($ALPlatformLayerLatestRevision.DisplayedVersion)]" -ForegroundColor Yellow
        Logaction "Most recent layer revision for [$($ALPlatformLayer.Name)] is [$($ALPlatformLayerLatestRevision.DisplayedVersion)]"
    
        # Retrieve all but the last two layerrevisions which can be deleted and being older than than the mPlatformt recent assigned revision
        $AllPlatformLayerRevsCanDelete = $ALPlatformLayerRevisions.Revisions.PlatformLayerRevisionDetail | Where-Object {$_.Candelete -eq $True -and ($_.DisplayedVersion -lt $ALPlatformLayerLatestRevision.DisplayedVersion)} | Sort-Object DisplayedVersion | Select-Object -SkipLast 2
        if ($AllPlatformLayerRevsCanDelete -eq $null){
            Write-Host "$(Write-TimeIndent) No obsolete layer revisionsavailable for layer: [$($ALPlatformLayer.Name)], Continue" -ForegroundColor Yellow
            Logaction "No obsolete layer revisions available for layer: [$($ALPlatformLayer.Name)], Continue"
            Continue
        }

        Write-Host "$(Write-TimeIndent) The following layer revisions are candidates to be removed: [$($AllPlatformLayerRevsCanDelete.DisplayedVersion -join ('|'))]" -ForegroundColor Yellow
        Logaction "The following layer revisions are candidates to be removed: [$($AllPlatformLayerRevsCanDelete.DisplayedVersion -join ('|'))]"

        foreach ($PlatformLayerRevCanDelete in $AllPlatformLayerRevsCanDelete){
            Write-Host "$(Write-TimeIndent) Process Layer Revision [$($PlatformLayerRevCanDelete.DisplayedVersion)] with id [$($PlatformLayerRevCanDelete.id)])" -ForegroundColor Yellow
            Logaction "Process Layer Revision [$($PlatformLayerRevCanDelete.DisplayedVersion)] with id [$($PlatformLayerRevCanDelete.id)])"
            
            Try 
            {
                Remove-ALPlatformLayerRev -websession $ALWebSession -Platformid $PlatformLayerRevCanDelete.Layerid -Platformrevid $PlatformLayerRevCanDelete.id -fileshareid $fileshare.id -OutVariable PlatformLayerRevDeleted -Confirm:$false | Out-Null
            }   Catch [Exception] 
            {
                Write-Error "$(Write-TimeIndent) Remove-ALPlatformLayerRev - $_"
                Logaction "Remove-ALAppLayerRev - $_"
            }
                    
                # Get-Status and loop while task status is running
                $DeleteRevStatus = Get-ALStatus -id $PlatformLayerRevDeleted.WorkTicketId -websession $ALWebSession
                
                $a = 0
                Do {
                    IF ($a -eq "99") {$a=0}
                    if (($DeleteRevStatus.Status -notlike "Running") -and ($DeleteRevStatus.Status -notlike "Pending")){
                        $a=100
		                Write-Progress -Activity "Deleting Layer Revision is ready..." -PercentComplete $a -Status "Finish."
		                Start-Sleep 2
                        Write-Progress "Done" "Done" -completed	
		                break
	                } ELSE {
                        $DeleteRevStatus = Get-ALStatus -id $PlatformLayerRevDeleted.WorkTicketId -websession $ALWebSession | Out-Null
                        $a++
		                Write-Progress -Activity "Creating new layer revision is in [$($DeleteRevStatus.Status)] state, waiting until finished..." -PercentComplete $a -Status "Please wait..."
		                Start-Sleep 0.5
                        }
                    } While ($a -ne 100)

                # Verify if layer revisions has been deleted
                if ((Get-ALPlatformLayerDetail -websession $ALWebSession -id $ALPlatformLayer.Id).Revisions.PlatformLayerRevisionDetail | Where-Object {$_.id -eq $PlatformLayerRevCanDelete.id} -eq $null)
                {
                    Write-Host "$(Write-TimeIndent) Successfull removed revision for layer: [$($ALPlatformLayer.Name)] with version: [$($PlatformLayerRevCanDelete.DisplayedVersion)] and id [$($PlatformLayerRevCanDelete.id)])" -ForegroundColor Green
                    Logaction "Successfull removed revision for layer: [$($ALPlatformLayer.Name)] with version: [$($PlatformLayerRevCanDelete.DisplayedVersion)] and id [$($PlatformLayerRevCanDelete.id)])"
                } 
                Else 
                {
                    Write-Error "$(Write-TimeIndent) Removal of revision for layer: [$($ALPlatformLayer.Name)] with version: [$($PlatformLayerRevCanDelete.DisplayedVersion)] and id [$($PlatformLayerRevCanDelete.id)]) FAILED - $_"
                    Logaction "Removal of revision for layer: [$($ALPlatformLayer.Name)] with version: [$($PlatformLayerRevCanDelete.DisplayedVersion)] and id [$($PlatformLayerRevCanDelete.id)]) FAILED - $_"
                }
        }
    }
}

# DisConnect from Appliances
disconnect-alsession -websession $ALWebSession
###
Write-Host "$(Write-TimeNumberSign) *** READY ***" -ForegroundColor Green
Logaction "*** READY ***"