<# 
    .Synopsis 
        ---- Checks if the latest matching image revisions include the latest OS, Publisng and Office layer revision ----
        --- Based on reversed Engineered Powershell SDK for Citrix Application Layering ---
    .Description 
        Checks if the latest matching image revisions include the latest OS, Publisng and Office layer revision
    .Example 
        CAL_PowerShell_SDK_Update_Image -environment DTA -Credential $Credential
    .Notes
        Author: Siebrand Feenstra - s.feenstra@loginconsultants.nl
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

# Provide Global Variables ###
$VerbosePreference = "silentlycontinue"
$ALOSLayerName = "W10_OS_1803" # <<-- Name of the OS layer that you would like to use
$ALOSLayerRevisionName = "1803S" # <<-- Name of the OS Layer Revision that the revision should match
$ALPLPubLayerName = "W10_PL_PUB"
$ALAPPLayerNames = @("W10_APP_Office_2016","W10_APP_GENERAL","W10_APP_CORE","W10_APP_Optimize_R")
if ($Environment -eq "DTA"){$apdevlip = "agofxdelmd01.nac.ppg.com"}
elseif ($Environment -eq "PROD"){$apdevlip = "agofxdelm01.nac.ppg.com"}

# LOGGING and FUNCTIONS
$logpath = "\\nac.ppg.com\dfs\Citrix\Sources\XD\Scripts\Logs"
if (!(test-path $logpath)){try{New-Item -ItemType directory -Path $loglocation -Force}catch [Exception]{Write-warning $_.Exception.Message}}
$LogFile = "CAL_PowerShell_SDK_Update_Images.log"
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
Logaction "--- CAL_PowerShell_SDK_Update_Images ---"

# MODULES -----------------------
Import-Module "$(Get-ScriptDirectory)\LIC_Function_Library.psm1" -DisableNameChecking
Import-Module -Name ctxal-sdk

# Verify credentials
if ($Credential -ne [System.Management.Automation.PSCredential]::Empty)
{
    
    if ((Test-ADCredential -Credential $Credential) -eq $false)
    {
        [int]$Credtestcount = '1'
        DO 
        {
            Write-Host "$(Write-TimeNumberSign) Credential incorrect [$Credtestcount/3]" -ForegroundColor Red
            $Credential = $host.ui.PromptForCredential("Connecting CAL appliance", "Please enter your user name and password to access the CAL appliance.","", "")
            $Credtestcount += '1'
        
        } until ((Test-ADCredential -Credential $Credential) -eq $true -or $Credtestcount -gt '3')

        Write-Host "$(Write-TimeNumberSign) credentials provided incorrectly 3 times. EXITING" -ForegroundColor Red
        break 
    } 
    
    if ((Test-ADCredential -Credential $Credential) -eq $true){
        Write-Host "$(Write-TimeNumberSign) Credential verified" -ForegroundColor Green
    }

} else {
        
    Write-Host "$(Write-TimeNumberSign) No credentials provided. EXITING" -ForegroundColor Red
    break 
}

# Connect to the DEV Appliance
Write-Host "$(Write-TimeNumberSign) Selected Applicance: [$($apdevlip.ToUpper())]" -ForegroundColor Yellow
$ALWebSession = Connect-alsession -aplip $apdevlip -Credential $Credential

# SCRIPT ------------------------
Write-Host "$(Write-TimeNumberSign) Retrieve layer information and create new layer revision when it needs to be updated" -ForegroundColor Yellow

# Get ID of latest OS layer revision
$ALOSLayerRevisions = Get-ALOsLayerDetail -id $(Get-ALOsLayer -websession $ALWebSession | Where-Object {$_.Name -eq $ALOSLayerName}).Id -websession $ALWebSession
$ALOSLayerLatestRevision = $ALOSLayerRevisions.Revisions.OsLayerRevisionDetail | Where-Object {$_.DisplayedVersion -match $ALOSLayerRevisionName} | Where-Object {$_.State -eq "Deployable"} | Sort-Object DisplayedVersion -Descending | Select-Object -First 1

# Get ID of latest PlatForm layer revision
$ALPLLayerRevisions = Get-ALPlatformLayerDetail -id $(Get-ALPlatformlayer -websession $ALWebSession | Where-Object {$_.Name -eq $ALPLPubLayerName}).Id -websession $ALWebSession
$ALPLLayerLatestRevision = $ALPLLayerRevisions.Revisions.PlatformLayerRevisionDetail | Where-Object {$_.State -eq "Deployable"} | Sort-Object DisplayedVersion -Descending | Select-Object -First 1

Write-Host "$(Write-TimeNumberSign) App Layers to check for: [$($ALAPPLayerNames -join(' | '))]"
Logaction "App Layers to check for: [$($ALAPPLayerNames -join(' | '))]"

# Get ID of latest Application Layers provided
if (![string]::IsNullOrWhiteSpace($ALAPPLayerNames)){
    $ALAppLayerRevisions = foreach ($ALAPPLayerName in $ALAPPLayerNames){Get-ALapplayerDetail -id $(Get-ALapplayer -websession $ALWebSession | Where-Object {$_.Name -eq $ALAPPLayerName}).Id -websession $ALWebSession}
    $ALAppLayerLatestRevision = foreach ($ALAppLayerRevision in $ALAppLayerRevisions){$ALAppLayerRevision.Revisions.AppLayerRevisionDetail | Where-Object {$_.State -eq "Deployable"} | Sort-Object DisplayedVersion -Descending | Select-Object -First 1}
}

#Get Image Composition
$NPImages = Get-ALImageComp -websession $ALWebSession

if ($NPImages -eq $null){
Write-Host "$(Write-TimeNumberSign) No Image selected. EXITING" -ForegroundColor Red
break
}

Write-Host "$(Write-TimeIndent) Retrieve matching image names" -ForegroundColor Yellow
$my_match_list = @($NPImages.Name -match "[R]_[W]\d{2}_[A-Z]{3,5}_(IMG)_[R]\d{3}" | ForEach-Object{$_.Substring(0, $_.LastIndexOf("R"))} | Select-Object -Unique)
$my_strings_list = @($NPImages.Name -match "[R]_[W]\d{2}_[A-Z]{3,5}_(IMG)_[R]\d{3}")

foreach($i in $my_match_list){
Write-Host "$(Write-TimeIndent) matching item: $i" -ForegroundColor Yellow

    # ($my_matchList[0]|$Mymatchlist[1]|...)
    [regex]$Match_regex = ‘(‘ + (($i |ForEach-Object {[regex]::escape($_)}) –join “|”) + ‘)’

    # Get matching items based on the match item in the list of images and select any other that the last 3
    $Selection = $my_strings_list -match $Match_regex | Sort-Object -Descending | Select-Object -First 1
    if ($Selection -eq $null){Write-Host "$(Write-TimeIndent) Nothing to do for matching item: $i" -ForegroundColor Green;Continue}
    
    # Get Image Details
    $ImageDetails = Get-ALimageDetail -websession $ALWebSession -id $(Get-ALimage -websession $ALWebSession | Where-Object {$_.Name -match $Selection}).Id
    
    Write-Host "$(Write-TimeIndent) The following Image revision is to be verified: [$($ImageDetails.Name)]" -ForegroundColor Yellow
    Logaction "The following Image revision is to be verified: [$($ImageDetails.Name)]"

    # Retrive OS Layer Revision for the Selected Image and verify ID with the latest OS Layer Revision
    $ALSelectedImgOSLayerRev = (Get-ALimageDetail -websession $ALWebSession -id $($ImageDetails.id)).OsRev.Revisions.RevisionResult
    $ALSelectedImgPLLayerRev = (Get-ALimageDetail -websession $ALWebSession -id $($ImageDetails.id)).PlatFormLayer.Revisions.RevisionResult
    
    if (![string]::IsNullOrWhiteSpace($ALAPPLayerNames))
    {$ALSelectedImgAppLayerRevs = foreach ($ALAPPLayerName in $ALAPPLayerNames){((Get-ALimageDetail -websession $ALWebSession -id $($ImageDetails.id)).AppLayers.ApplicationLayerResult | Where-Object {$_.Name -eq $ALAPPLayerName}).Revisions.RevisionResult}}    
    
        # Set Update is Needed flag to false
        $ImageNeedsUpdate = $false

        # Check if OS Layer revision in the image is the latest
        if ($ALOSLayerLatestRevision.id -ne $ALSelectedImgOSLayerRev.id)
        {
            Write-Host "$(Write-TimeIndent) OS Layer revision for [$Selection] is not up to date!" -ForegroundColor DarkYellow
            Logaction "OS Layer revision for [$Selection] is not up to date!"
            $ImageNeedsUpdate = $true
        }
        
        # Check if Platform Layer revision in the image is the latest
        if ($ALPLLayerLatestRevision.id -ne $ALSelectedImgPLLayerRev.id)
        {
            Write-Host "$(Write-TimeIndent) Platform Layer revision for [$Selection] is not up to date!" -ForegroundColor DarkYellow
            Logaction "Platform Layer revision for [$Selection] is not up to date!"
            $ImageNeedsUpdate = $true
        }

        # Check if Office Applicatoon Layer revision in the image is the latest
        if ((![string]::IsNullOrWhiteSpace($ALAppLayerLatestRevision)) -and (![string]::IsNullOrWhiteSpace($ALSelectedImgAppLayerRevs)))
        {
            $ALAppLayerLatestRevsDiff = Compare-Object -ReferenceObject ($ALAppLayerLatestRevision | Sort-Object DisplayedVersion) -DifferenceObject ($ALSelectedImgAppLayerRevs | Sort-Object Name) -Property Id -IncludeEqual -PassThru | Where-Object{$_.Sideindicator -eq '=>'}

            if ($ALAppLayerLatestRevsDiff -ne $null){
                foreach ($ALAppLayerLatestRevDiff in $ALAppLayerLatestRevsDiff)
                    {
                        Write-Host "$(Write-TimeIndent) Application Layer revision [$($ALAppLayerLatestRevDiff.name)] for [$Selection] is not up to date!" -ForegroundColor DarkYellow
                        Logaction "Application Layer revision for [$Selection] is not up to date!"
                        $ImageNeedsUpdate = $true
                    }
            }
        }

    if ($ImageNeedsUpdate -eq $true)
    {
        Write-Host "$(Write-TimeIndent) The following Image revision is to be Cloned: [$Selection]" -ForegroundColor Yellow
        Logaction "The following Image revision is to be Cloned: [$Selection]"

        # Retrieve current Revision name, increase the numeric part based on a 3 decimal numeric value, and combine them again.
        $Index = [int]$Selection.Substring($Selection.LastIndexOf("_R")+2);$Index++   
        $ClonedVersionNew = ($Selection.Substring(0,$Selection.LastIndexOf("_R")) + "_R{0:000}" -f $Index)
        Write-Host "$(Write-TimeIndent) The previous revision was [$($Selection)] and the new will be [$ClonedVersionNew]" -ForegroundColor Cyan
        Logaction "The previous revision was [$($Selection)] and the new will be [$ClonedVersionNew]"

            Try {
                New-ALImageClone -websession $ALWebSession -imageid $ImageDetails.Id -Confirm:$false -OutVariable ALImageClone | out-null
                Write-Host "$(Write-TimeIndent) CloneOperation SUCCEEDED for [$ClonedVersionNew]" -ForegroundColor Green
                Logaction "CloneOperation SUCCEEDED for [$ClonedVersionNew]"    
            } catch [Exception] 
            {
                Write-Host "$(Write-TimeIndent) CloneOperation failed for [$ClonedVersionNew] - $_" -ForegroundColor Red
                Logaction "CloneOperation failed for [$ClonedVersionNew]"
                Continue
            }

            Try {Set-alimage -websession $ALWebSession -name $ClonedVersionNew -description "Auto Cloned - $($ImageDetails.Name)"`
             -osrevid $ALOSLayerLatestRevision.Id -platrevid $ALPLLayerLatestRevision.id -id $ALImageClone.ImageSummary.Id`
             -ElasticLayerMode $($ImageDetails.ElasticLayerMode) -Confirm:$false -OutVariable SetImage -applayerid $ALAppLayerLatestRevision.LayerId -apprevid $ALAppLayerLatestRevision.Id | out-null
            Write-Host "$(Write-TimeIndent) Edit Clone operation SUCCEEDED for [$ClonedVersionNew]" -ForegroundColor Green
            Logaction "Edit Clone operation SUCCEEDED for [$ClonedVersionNew]"        
            } catch [Exception] 
            {
                Write-Host "$(Write-TimeIndent) Edit Clone operation failed for [$ClonedVersionNew] - $_" -ForegroundColor Red
                Logaction "Edit Clone operation failed for [$ClonedVersionNew] - $_"
                Continue
            }
    
    } Else {
        Write-Host "$(Write-TimeIndent) [OK] - Nothing to do!" -ForegroundColor Green
        Logaction "[OK] - Nothing to do! - $_"
    }

    Write-Host "[DONE]" -ForegroundColor Yellow
    Logaction "[DONE]"

}

# DisConnect from Appliances
disconnect-alsession -websession $ALWebSession
###
Write-Host "$(Write-TimeNumberSign) *** READY ***" -ForegroundColor Green
Logaction "*** READY ***"