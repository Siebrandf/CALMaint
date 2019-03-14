<# 
    .Synopsis 
        --- Housekeeping the App Layering Applicance by removal of obsolete layer revisions ---
    .Description 
        Retrievs all revisions available for a given Layer type (OS, Platform or App) and delete the ones not assigned while keep the last two.
    .Example 
        CAL_PowerShell_SDK_Cleanup_Obsolete_Revisions_V1.0.ps1 -LayerType AppLayer -Environment DTA -Confirm $false
    #>
     param(
    # The LayerType to process, either OSLayer, PlatFormLayer or Applayer.
    [parameter(Mandatory=$true)]
    [ValidateSet("OSLayer", "PlatFormLayer",  "AppLayer")]
    $LayerType,
    [parameter(Mandatory=$false)]
    [ValidateSet("DTA", "PROD")]
    $Environment = "DTA",
    [parameter(Mandatory=$false)]
    [ValidateSet($true, $false)]
    $Confirm = $true    
    )  

# Define error action preference
$ErrorActionPreference = "Continue"

# Define Script Variables
$DevCalApl = "yourdevapplianceunchere"
$ProdCalApl = "yourdevapplianceunchere"
$Skiplast "2"

function Get-ScriptDirectory {
    if ($psise) {Split-Path $psise.CurrentFile.FullPath}
    else {Split-Path $script:MyInvocation.MyCommand.Path}
}

# MODULES -----------------------
Import-Module "$(Get-ScriptDirectory)\LIC_Function_Library.psm1" -DisableNameChecking
# Update-Module -Name ctxal-sdk

# Appliance Creds
Write-Host "$(Write-TimeNumberSign) Please enter your user name and password to access the CAL appliance." -ForegroundColor Yellow
$Credential = $host.ui.PromptForCredential("Connecting Appliance", "Please enter your user name and password to access the CAL appliance.","", "")
if ($Credential -eq $null){
    Write-Error "$(Write-TimeNumberSign) No credentials provided. EXITING"
    break
}

# Connect to the Appliance
if ($Environment -eq "DTA"){$calapl = $DevCalApl}
elseif ($Environment -eq "PROD"){$calapl = $ProdCalApl}
Write-Host "$(Write-TimeNumberSign) Selected Applicance: [$($calapl.ToUpper())]" -ForegroundColor Yellow
$ALWebSession = Connect-alsession -aplip $calapl -Credential $Credential

# Get Fileshare details from the appliance
$fileshare = Get-ALRemoteshare -websession $ALWebSession
if ($fileshare -eq $null){Write-Error "$(Write-TimeIndent) Fileshare could not be determined. EXITING...";Break}

# Create an Array including all layers revision details. 
$AllAppLayersCanDelete = [System.Collections.ArrayList]@()

### Script ####

if ($LayerType -eq "AppLayer"){
Write-Host "$(Write-TimeIndent) Layer to process is of type: $LayerType" -ForegroundColor Yellow

    # Get teh layers for the given layertype
    Write-Host "$(Write-TimeIndent) Retrieve all Layers of type: $LayerType" -ForegroundColor Yellow
    $ALAppLayers = Get-ALAppLayer -websession $ALWebSession
 
    Foreach ($ALAppLayer in $ALAppLayers){
            
        # Get ID of latest App layer revision
        Write-Host "$(Write-TimeIndent) Process layer [$($ALAppLayer.Name)]" -ForegroundColor Cyan
        $ALAppLayerRevisions = Get-ALAppLayerDetail -websession $ALWebSession -id $ALAppLayer.Id
        $ALAppLayerLatestRevision = $ALAppLayerRevisions.Revisions.AppLayerRevisionDetail | Where-Object {$_.State -eq "Deployable"} | Sort-Object DisplayedVersion -Descending | Select-Object -First 1
        Write-Host "$(Write-TimeIndent) Most recent layer revision for [$($ALAppLayer.Name)] is [$($ALAppLayerLatestRevision.DisplayedVersion)]" -ForegroundColor Yellow
            
        # Retrieve all but the last two layerrevisions which can be deleted and being older than than the most recent assigned revision
        $AllAppLayerRevsCanDelete = $ALAppLayerRevisions.Revisions.AppLayerRevisionDetail | where {$_.Candelete -eq $True -and ($_.DisplayedVersion -lt $ALAppLayerLatestRevision.DisplayedVersion)} | sort DisplayedVersion | select -SkipLast $Skiplast
        if ($AllAppLayerRevsCanDelete -eq $null){
            Write-Host "$(Write-TimeIndent) No obsolete layer revisionsavailable for layer: [$($ALAppLayer.Name)], Continue" -ForegroundColor Yellow
            Continue
        }

        Write-Host "$(Write-TimeIndent) The following layer revisions are candidates to be removed: [$($AllAppLayerRevsCanDelete.DisplayedVersion -join ('|'))]" -ForegroundColor Yellow

        foreach ($AppLayerRevCanDelete in $AllAppLayerRevsCanDelete){
            Write-Host "$(Write-TimeIndent) Process Layer Revision [$($AppLayerRevCanDelete.DisplayedVersion)] with id [$($AppLayerRevCanDelete.id)])" -ForegroundColor Yellow
            Try {Remove-ALAppLayerRev -websession $ALWebSession -appid $AppLayerRevCanDelete.Layerid -apprevid $AppLayerRevCanDelete.id -fileshareid $fileshare.id -OutVariable AppLayerRevDeleted -Confirm:$Confirm | Out-Null
            } Catch [Exception] {Write-Error "$(Write-TimeIndent) Remove-ALAppLayerRev - $_"}
                    
                # Get-Status and loop while task status is running
                $DeleteRevStatus = Get-ALStatus -id $AppLayerRevDeleted.WorkTicketId -websession $ALWebSession
                
                $a = 0
                Do {
                    IF ($a -eq "99") {$a=0}
                    if (($DeleteRevStatus.Status -notlike "Running") -and ($DeleteRevStatus.Status -notlike "Pending")){
                        $a=100
		                Write-Progress -Activity "Deleteing Layer Revision is ready..." -PercentComplete $a -Status "Finish."
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

                # Verify if layer revisions has been deleted
                if ((Get-ALAppLayerDetail -websession $ALWebSession -id $ALAppLayer.Id).Revisions.AppLayerRevisionDetail | Where {$_.id -eq $AppLayerRevCanDelete.id} -eq $null){
                    Write-Host "$(Write-TimeIndent) Successfull removed revision for layer: [$($ALAppLayer.Name)] with version: [$($AppLayerRevCanDelete.DisplayedVersion)] and id [$($AppLayerRevCanDelete.id)])" -ForegroundColor Green
                } Else {Write-Error "$(Write-TimeIndent) Removal of revision for layer: [$($ALAppLayer.Name)] with version: [$($AppLayerRevCanDelete.DisplayedVersion)] and id [$($AppLayerRevCanDelete.id)]) FAILED - $_"}
        }
    }
}

if ($LayerType -eq "OsLayer"){
Write-Host "$(Write-TimeIndent) Layer to process is of type: $LayerType" -ForegroundColor Yellow

    # Get ID of latest layer revision    
    Write-Host "$(Write-TimeIndent) Retrieve all Layers of type: $LayerType" -ForegroundColor Yellow
    $ALOsLayers = Get-ALOsLayer -websession $ALWebSession
 
    Foreach ($ALOsLayer in $ALOsLayers){
            
        # Get ID of latest Os layer revision
        Write-Host "$(Write-TimeIndent) Process layer [$($ALOsLayer.Name)]" -ForegroundColor Cyan
        $ALOsLayerRevisions = Get-ALOsLayerDetail -websession $ALWebSession -id $ALOsLayer.Id
        $ALOsLayerLatestRevision = $ALOsLayerRevisions.Revisions.OsLayerRevisionDetail | Where-Object {($_.State -eq "Deployable") -and ($_.DisplayedVersion -notmatch "1803R")} | Sort-Object DisplayedVersion -Descending | Select-Object -First 1
        Write-Host "$(Write-TimeIndent) Most recent layer revision for [$($ALOsLayer.Name)] is [$($ALOsLayerLatestRevision.DisplayedVersion)]" -ForegroundColor Yellow
            
        # Retrieve all but the last two layerrevisions which can be deleted and being older than than the most recent assigned revision
        $AllOsLayerRevsCanDelete = $ALOsLayerRevisions.Revisions.OsLayerRevisionDetail | where {$_.Candelete -eq $True -and ($_.DisplayedVersion -lt $ALOsLayerLatestRevision.DisplayedVersion) -and ($_.DisplayedVersion -notmatch "1803R")} | sort DisplayedVersion | select -SkipLast $Skiplast
        if ($AllOsLayerRevsCanDelete -eq $null){
            Write-Host "$(Write-TimeIndent) No obsolete layer revisionsavailable for layer: [$($ALOsLayer.Name)], Continue" -ForegroundColor Yellow
            Continue
        }

        Write-Host "$(Write-TimeIndent) The following layer revisions are candidates to be removed: [$($AllOsLayerRevsCanDelete.DisplayedVersion -join ('|'))]" -ForegroundColor Yellow

        foreach ($OsLayerRevCanDelete in $AllOsLayerRevsCanDelete){
            Write-Host "$(Write-TimeIndent) Process Layer Revision [$($OsLayerRevCanDelete.DisplayedVersion)] with id [$($OsLayerRevCanDelete.id)])" -ForegroundColor Yellow
            Try {Remove-ALOsLayerRev -websession $ALWebSession -Osid $OsLayerRevCanDelete.Layerid -Osrevid $OsLayerRevCanDelete.id -fileshareid $fileshare.id -OutVariable OsLayerRevDeleted -Confirm:$Confirm| Out-Null
            } Catch [Exception] {Write-Error "$(Write-TimeIndent) Remove-ALOsLayerRev - $_"}
                    
                # Get-Status and loop while task status is running
                $DeleteRevStatus = Get-ALStatus -id $OsLayerRevDeleted.WorkTicketId -websession $ALWebSession
                
                $a = 0
                Do {
                    IF ($a -eq "99") {$a=0}
                    if (($DeleteRevStatus.Status -notlike "Running") -and ($DeleteRevStatus.Status -notlike "Pending")){
                        $a=100
		                Write-Progress -Activity "Deleteing Layer Revision is ready..." -PercentComplete $a -Status "Finish."
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
                if ((Get-ALOsLayerDetail -websession $ALWebSession -id $ALOsLayer.Id).Revisions.OsLayerRevisionDetail | Where {$_.id -eq $OsLayerRevCanDelete.id} -eq $null){
                    Write-Host "$(Write-TimeIndent) Successfull removed revision for layer: [$($ALOsLayer.Name)] with version: [$($OsLayerRevCanDelete.DisplayedVersion)] and id [$($OsLayerRevCanDelete.id)])" -ForegroundColor Green
                } Else {Write-Error "$(Write-TimeIndent) Removal of revision for layer: [$($ALOsLayer.Name)] with version: [$($OsLayerRevCanDelete.DisplayedVersion)] and id [$($OsLayerRevCanDelete.id)]) FAILED - $_"}
        }
    }
}

if ($LayerType -eq "PlatformLayer"){
Write-Host "$(Write-TimeIndent) Layer to process is of type: $LayerType" -ForegroundColor Yellow

    # Get ID of latest layer revision    
    Write-Host "$(Write-TimeIndent) Retrieve all Layers of type: $LayerType" -ForegroundColor Yellow
    $ALPlatformLayers = Get-ALPlatformLayer -websession $ALWebSession
 
    Foreach ($ALPlatformLayer in $ALPlatformLayers){
            
        # Get ID of latest Platform layer revision
        Write-Host "$(Write-TimeIndent) Process layer [$($ALPlatformLayer.Name)]" -ForegroundColor Cyan
        $ALPlatformLayerRevisions = Get-ALPlatformLayerDetail -websession $ALWebSession -id $ALPlatformLayer.Id
        $ALPlatformLayerLatestRevision = $ALPlatformLayerRevisions.Revisions.PlatformLayerRevisionDetail | Where-Object {$_.State -eq "Deployable"} | Sort-Object DisplayedVersion -Descending | Select-Object -First 1
        Write-Host "$(Write-TimeIndent) MPlatformt recent layer revision for [$($ALPlatformLayer.Name)] is [$($ALPlatformLayerLatestRevision.DisplayedVersion)]" -ForegroundColor Yellow
            
        # Retrieve all but the last two layerrevisions which can be deleted and being older than than the mPlatformt recent assigned revision
        $AllPlatformLayerRevsCanDelete = $ALPlatformLayerRevisions.Revisions.PlatformLayerRevisionDetail | where {$_.Candelete -eq $True -and ($_.DisplayedVersion -lt $ALPlatformLayerLatestRevision.DisplayedVersion)} | sort DisplayedVersion | select -SkipLast $Skiplast
        if ($AllPlatformLayerRevsCanDelete -eq $null){
            Write-Host "$(Write-TimeIndent) No obsolete layer revisionsavailable for layer: [$($ALPlatformLayer.Name)], Continue" -ForegroundColor Yellow
            Continue
        }

        Write-Host "$(Write-TimeIndent) The following layer revisions are candidates to be removed: [$($AllPlatformLayerRevsCanDelete.DisplayedVersion -join ('|'))]" -ForegroundColor Yellow

        foreach ($PlatformLayerRevCanDelete in $AllPlatformLayerRevsCanDelete){
            Write-Host "$(Write-TimeIndent) Process Layer Revision [$($PlatformLayerRevCanDelete.DisplayedVersion)] with id [$($PlatformLayerRevCanDelete.id)])" -ForegroundColor Yellow
            Try {Remove-ALPlatformLayerRev -websession $ALWebSession -Platformid $PlatformLayerRevCanDelete.Layerid -Platformrevid $PlatformLayerRevCanDelete.id -fileshareid $fileshare.id -OutVariable PlatformLayerRevDeleted -Confirm:$Confirm | Out-Null
            } Catch [Exception] {Write-Error "$(Write-TimeIndent) Remove-ALPlatformLayerRev - $_"}
                    
                # Get-Status and loop while task status is running
                $DeleteRevStatus = Get-ALStatus -id $PlatformLayerRevDeleted.WorkTicketId -websession $ALWebSession
                
                $a = 0
                Do {
                    IF ($a -eq "99") {$a=0}
                    if (($DeleteRevStatus.Status -notlike "Running") -and ($DeleteRevStatus.Status -notlike "Pending")){
                        $a=100
		                Write-Progress -Activity "Deleteing Layer Revision is ready..." -PercentComplete $a -Status "Finish."
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
                if ((Get-ALPlatformLayerDetail -websession $ALWebSession -id $ALPlatformLayer.Id).Revisions.PlatformLayerRevisionDetail | Where {$_.id -eq $PlatformLayerRevCanDelete.id} -eq $null){
                    Write-Host "$(Write-TimeIndent) Successfull removed revision for layer: [$($ALPlatformLayer.Name)] with version: [$($PlatformLayerRevCanDelete.DisplayedVersion)] and id [$($PlatformLayerRevCanDelete.id)])" -ForegroundColor Green
                } Else {Write-Error "$(Write-TimeIndent) Removal of revision for layer: [$($ALPlatformLayer.Name)] with version: [$($PlatformLayerRevCanDelete.DisplayedVersion)] and id [$($PlatformLayerRevCanDelete.id)]) FAILED - $_"}
        }
    }
}

# DisConnect from Appliances
disconnect-alsession -websession $ALWebSession
###
Write-Host "$(Write-TimeNumberSign) *** READY ***" -ForegroundColor Green
