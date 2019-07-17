<# 
    .Synopsis 
        ---- Create App Layer on Citrix App Layering and VMware vSphere ----
        Run on management server with PowerCLI installed
    .Description 
        A Detailed Description of what the command does 
    .Example 
        CAL_PowerShell_SDK_WSUS_Update_Layer_V1.0 -LayerType OS
    .Notes
        Author: Siebrand Feenstra - s.feenstra@loginconsultants.nl
#>

[cmdletbinding(SupportsShouldProcess=$True)]

param(
[parameter(Mandatory=$false)]
[ValidateSet("YES", "NO")]
$publish = "NO", #define if image need to be published or not
[parameter(Mandatory=$false)]
$Inputpath, # provide the path to the Images4$Environment.json file containing the references names for the images to export
[ValidateNotNull()]
[System.Management.Automation.PSCredential]
[System.Management.Automation.Credential()]
$Credential = [System.Management.Automation.PSCredential]::Empty
)

# Define error action preference
$ErrorActionPreference = "Continue"

# Variables
$Skiplast = "3"
$DTAApliance = "DTAAppliancehere"
$PRODAppliance = "PRODAppliancehere"
$logpath = "loguncpathhere"

# LOGGING and FUNCTIONS
if (!(test-path $logpath)){try{New-Item -ItemType directory -Path $loglocation -Force}catch [Exception]{Write-warning $_.Exception.Message}}
$LogFile = "CAL_PowerShell_SDK_Clone_Image.log"
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
Logaction "--- CAL_PowerShell_SDK_Clone_Image ---"

# MODULES -----------------------
Import-Module "$(Get-ScriptDirectory)\LIC_Function_Library.psm1" -DisableNameChecking
write-host
# Install-Module -Name ctxal-sdk # needs elevation
# Update-Module -Name ctxal-sdk # needs elevation

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
    if ((test-path -Path "$Inputpath\Images4PROD.json" -ea 0) -eq $true)
    {            
        $inputfile = $("$Inputpath\Images4PROD.json")
        Write-Host "$(Write-TimeNumberSign) Inputfile provided [$inputfile]" -ForegroundColor Cyan
    }
    else {$inputfile = $null}
}

# Assign credentials for the account with access to the share
$mypath = "\\sgofctxstorenw.nac.ppg.com\layers$"
$myusername = $Credential.Username
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
$sharepw = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

# Connect to the DEV Appliance
$websessionDEV = Connect-alsession -aplip $DTAApliance -Credential $Credential

# Connect to the PROD Appliance
$websessionPROD = Connect-alsession -aplip $PRODAppliance -Credential $Credential
$HVConnectorProd = "PPG_GOFVDIVSAN01_PROD" # Hypervisor Connector Prod

### Script ####

# If inputpath is provided read reference names from "$Inputpath\Images4$Environment.csv" otherwise
# Select image in gridview, multi select is possible

if ($inputfile -ne $null)
{
    # Read inputfile to retrieve reference names. this file can be build with Infra_Define_Images2Process.ps1
    try {$Images2Process = Get-Content $inputfile -ea Stop -Raw | ConvertFrom-Json
        } catch [Exception] {Write-Host "$(Write-TimeNumberSign) $_" -ForegroundColor RED}
    
    $ImagesDEV = @()

    if ($Images2Process){
        foreach ($Image2Process in $Images2Process){
        $ImagesDEV += Get-ALImageComp -websession $websessionDEV | Where-Object {$_.name -match "$($Image2Process.ImageReference)"} | Sort-Object Name -Descending | Select-Object -First 1
        }

        # When inputfile contains multiple equal ImageReferences for different catalogs select only the ones being unique
        $ImagesDEV = $ImagesDEV | Sort-Object Name -Unique

    }
    else
    {
        Write-Host "$(Write-TimeNumberSign) [$inputfile] is Empty" -ForegroundColor RED
        Break
    }
} 
else
{
    # Get Image Composition
    Write-Host "$(Write-TimeNumberSign) Select Image(s) to clone to PROD" -ForegroundColor Cyan
    $ImagesDEV = Get-ALImageComp -websession $websessionDEV | Where-Object {$_.name -match "[SR]_[W]\d{2}_[A-Z]{3,5}_(IMG)_[R]\d{3}"} | Sort-Object DateLastModified -Descending | Out-GridView -PassThru
}

if ($ImagesDEV -eq $null){
Write-Host "$(Write-TimeNumberSign) No Image selected. EXITING" -ForegroundColor Red
break
}

Write-Host "$(Write-TimeNumberSign) Images Queued: [$(($imagesdev | Measure-Object).Count)] - [$(($ImagesDEV.Name) -join(' | '))]" -ForegroundColor Yellow
Logaction "Images Queued: [$(($imagesdev | Measure-Object).Count)] - [$(($ImagesDEV.Name) -join(' | '))]"
Write-Host "$(Write-TimeNumberSign) Process EXPORT" -ForegroundColor Yellow
Logaction "Process EXPORT"

foreach ($imageDEV in $ImagesDEV)
{

    Write-Host "$(Write-TimeNumberSign) Image to process is: [$($imageDEV.Name)] - [$([array]::indexof($($imagesDEV.Name),$($imageDEV.Name)) +1)/$($imagesDEV.Name.Length)]" -ForegroundColor Magenta
    LogAction "Image to process is: [$($imageDEV.Name)] - [$([array]::indexof($($imagesDEV.Name),$($imageDEV.Name)) +1)/$($imagesDEV.Name.Length)]"

    # Create an Array including all layers revision details. 
    $AllLayersRevDetailsDEV = [System.Collections.ArrayList]@()
    $AllLayersRevDetailsDEV += ($(Get-ALOsLayer -websession $websessionDEV) | ForEach-Object {Get-ALOsLayerDetail -websession $websessionDEV -id $_.id}).revisions.oslayerrevisiondetail
    $AllLayersRevDetailsDEV += ($(Get-ALPlatformlayer -websession $websessionDEV) | ForEach-Object {Get-ALPlatformLayerDetail -websession $websessionDEV -id $_.id}).revisions.platformlayerrevisiondetail
    $AllLayersRevDetailsDEV += ($(Get-ALapplayer -websession $websessionDEV) | ForEach-Object {Get-ALapplayerDetail -websession $websessionDEV -id $_.id}).revisions.Applayerrevisiondetail

    # Compare the retrieved layer revision with the ones included in the image composition
    $ImageOSLayerDetails = Compare-Object -ReferenceObject $AllLayersRevDetailsDEV -DifferenceObject $ImageDEV.OsLayer -Property ID -IncludeEqual -ExcludeDifferent -PassThru
    $ImagePlatformLayerDetails = Compare-Object -ReferenceObject $AllLayersRevDetailsDEV -DifferenceObject $ImageDEV.PlatformLayer -Property ID -IncludeEqual -ExcludeDifferent -PassThru
    $ImageAppLayerDetails = Compare-Object -ReferenceObject $AllLayersRevDetailsDEV -DifferenceObject $ImageDEV.AppLayer -Property ID -IncludeEqual -ExcludeDifferent -PassThru

    # Create an new array including the Layer Name, id, revision, guid, status and priority. these property names are constant accross the import/export commandlets
    # the layer guid is retrieved being an unique layer identifier for comparision across appliances while the layer ID is unique with a specific appliance context. 
    $ImageLayersDEV = [System.Collections.ArrayList]@()
    $ImageLayersDEV += $ImageDEV.OSLayer | ForEach-Object{[pscustomobject]@{BaseName = $($_.Name).toupper();RevName = $($_.VersionNAME).toupper();ID = $($_.ID).toupper();Priority = $null;Status = $($_.Status).toupper();Guid = $($ImageOSLayerDetails.Guid).toupper();Type = "OsLayer"}}
    $ImageLayersDEV += $ImageDEV.PlatformLayer | ForEach-Object{[pscustomobject]@{BaseName = $($_.Name).toupper();RevName = $($_.VersionNAME).toupper();ID = $($_.ID).toupper();Priority = $null;Status = $($_.Status).toupper();;Guid = $($ImagePlatformLayerDetails.Guid).toupper();Type = "PlatFormLayer"}}
    $ImageLayersDEV += $ImageDEV.AppLayer | ForEach-Object{$i = 0}{[pscustomobject]@{BaseName = $($_.Name).toupper();RevName = $($_.VersionNAME).toupper();ID = $($_.ID).toupper();Priority = $($_.Priority).toupper();Status = $($_.Status).toupper();Guid = $($ImageAppLayerDetails | Where-Object {$_.id -like $ImageDEV.applayer[$i].Id}).Guid.toupper();Type = "AppLayer"};$i++}

    # Retrieve all exportable layers which are in the provided image
    $ExportLayerstoprocess = [System.Collections.ArrayList]@()
    $AllExportableLayers = Get-ALExportableRev -websession $websessionDEV -sharepath $mypath -username $myusername -sharepw $sharepw -showall
    $ExportLayerstoprocess += Compare-Object -ReferenceObject $AllExportableLayers -DifferenceObject $ImageLayersDEV -Property ID -IncludeEqual -ExcludeDifferent -PassThru

    # Export the Layers to process (not already on the share)
    $ExportLayerstoprocess | Where-Object {$_.ExistsInDestination -eq $false} | Export-ALlayerrev -websession $websessionDEV -sharepath $mypath -username $myusername -sharepw $sharepw -OutVariable ExportAlLayerRev | Out-Null

    # Get-Status and loop while task status is running
    $ExportAlLayerRevStatus = Get-ALStatus -id $ExportAlLayerRev -websession $websessionDEV

    Write-Host "$(Write-TimeNumberSign) Export Layer Revisions from the DEV Appliance not available under: [$mypath]" -ForegroundColor Yellow
    Logaction "Export Layer Revisions from the DEV Appliance not available under: [$mypath]"

    $a = 0
    Do {
    IF ($a -eq "99") {$a=0}
    if (($ExportAlLayerRevStatus.Status -notlike "Running") -and ($ExportAlLayerRevStatus.Status -notlike "Pending")){
        $a=100
		Write-Progress -Activity "Export Layer Revisions from the DEV Appliance Done" -PercentComplete $a -Status "Finish."
		Start-Sleep 1
		Write-Progress "Done" "Done" -completed	
		break
	} ELSE {
        $ExportAlLayerRevStatus = Get-ALStatus -id $ExportAlLayerRev -websession $websessionDEV
        $a++
		Write-Progress -Activity "Export Layer Revisions from the DEV Appliance is in [$($ExportAlLayerRevStatus.Status)] state, waiting until finished..." -PercentComplete $a -Status "Please wait..."
        start-sleep 5
        }
    } While ($a -ne 100)

    ###
    Write-Host "$(Write-TimeIndent) FINISHED Export" -ForegroundColor Green
    Logaction "FINISHED Export"
    
    Write-Host "$(Write-TimeNumberSign) Process IMPORT" -ForegroundColor Yellow
    Logaction "Process IMPORT"

    # Export Icon
    # Create IconExchange Path if not exist
    if ((Test-Path $($mypath + "\Unidesk\IconExchange")) -eq $false){New-Item -Path $($mypath + "\Unidesk\IconExchange") -ItemType Directory -Confirm:$false }

    $Icons = Get-ALicon -websession $websessionDEV
    $ImageIconassoc = $Icons | ForEach-Object{Get-ALiconassoc -iconid $_.iconid -websession $websessionDEV | Where-Object {$_.Name -eq $ImagesDEV.Name}}

    foreach($icon in $icons)
    {
        # No authentication needed to grab image
        Invoke-WebRequest -uri $($icon.url) -OutFile ("$Mypath\Unidesk\IconExchange\" + $($icon.iconid)+".png") -Credential $Credential
    }

    #### IMPORT ####

    # reconnect
    Write-Host "$(Write-TimeIndent) Reconnect to Prod Appliance" -ForegroundColor Yellow
    $websessionPROD = Connect-alsession -aplip $approdlip -Credential $Credential

    # Retrieve all importable layers for the provided image based on the ImageLayers Table defined previously
    Write-Host "$(Write-TimeIndent) Retrieve all importable layers" -ForegroundColor Yellow
    Logaction "Retrieve all importable layers"
    $ImportLayerstoprocess = [System.Collections.ArrayList]@()
    $AllImportableLayers = Get-ALImportableRev -websession $websessionPROD -sharepath $mypath -username $myusername -sharepw $sharepw -showall
    $ImportLayerstoprocess += Compare-Object -ReferenceObject $AllImportableLayers -DifferenceObject $ImageLayersDEV -Property BaseName, RevName -IncludeEqual -ExcludeDifferent -PassThru

    # Import the Image Layers to process (not already on the Appliance)
    $ImportLayerstoprocess | Where-Object {$_.ExistsInDestination -eq $false} | import-ALlayerrev -websession $websessionPROD -sharepath $mypath -username $myusername -sharepw $sharepw -OutVariable ImportAlLayerRev | Out-Null

    # Get-Status and loop while task status is running
    $ImportAlLayerRevStatus = Get-ALStatus -id $ImportAlLayerRev -websession $websessionPROD

    Write-Host "$(Write-TimeNumberSign) Import Layer Revisions which are not available on the PROD Appliance" -ForegroundColor Yellow
    Logaction "Import Layer Revisions which are not available on the PROD Appliance"

    $a = 0
    Do {
    IF ($a -eq "99") {$a=0}
    if (($ImportAlLayerRevStatus.Status -notlike "Running") -and ($ImportAlLayerRevStatus.Status -notlike "Pending")){
        $a=100
		Write-Progress -Activity "Import Layer Revisions which are not available on the PROD Appliance Done" -PercentComplete $a -Status "Finish."
		Start-Sleep 1
		Write-Progress "Done" "Done" -completed	
		break
	} ELSE {
        $ImportAlLayerRevStatus = Get-ALStatus -id $ImportAlLayerRev -websession $websessionPROD
        $a++
		Write-Progress -Activity "Import Layer Revisions is in [$($ImportAlLayerRevStatus.Status)] state, waiting until finished..." -PercentComplete $a -Status "Please wait..."
        start-sleep 5
        }
    } While ($a -ne 100)

    Write-Host "$(Write-TimeIndent) FINISHED Import" -ForegroundColor Green
    Logaction "FINISHED Import"
    Write-Host "$(Write-TimeNumberSign) Process Image Creation" -ForegroundColor Yellow
    Logaction "Process Image Creation"

    # Create an Array including all layers revision details.
    Write-Host "$(Write-TimeIndent) Create an Array including all layers revision details" -ForegroundColor Yellow
    $AllLayersRevDetailsPROD = [System.Collections.ArrayList]@()
    $AllLayersRevDetailsPROD += ($(Get-ALOsLayer -websession $websessionPROD) | ForEach-Object{Get-ALOsLayerDetail -websession $websessionPROD -id $_.id}).revisions.oslayerrevisiondetail
    $AllLayersRevDetailsPROD += ($(Get-ALPlatformlayer -websession $websessionPROD) | ForEach-Object{Get-ALPlatformLayerDetail -websession $websessionPROD -id $_.id}).revisions.platformlayerrevisiondetail
    $AllLayersRevDetailsPROD += ($(Get-ALapplayer -websession $websessionPROD) | ForEach-Object{Get-ALapplayerDetail -websession $websessionPROD -id $_.id}).revisions.Applayerrevisiondetail

    # Compare the available layer revisions between the available layers and the defined image layers 
    Write-Host "$(Write-TimeIndent) Compare the available layer revisions" -ForegroundColor Yellow
    Logaction "Compare the available layer revisions"
    $ImportedEqualLayerDetails = Compare-Object -ReferenceObject $AllLayersRevDetailsPROD -DifferenceObject $ImageLayersDEV -Property Guid -IncludeEqual -ExcludeDifferent -PassThru

    # In three steps for each LayerTpe;
    # 1. Get layer ID(s) of the specified type filtered on guid matching the one(s) being imported.
    # 2. Get all available Layer revisions for the previous retrieved Layer(s) in step #1
    # 3. Retrieve the layerrevision Id matching the guid in the ImageLayers table created prior to the export
    # 4. Store the Layer revision Id to be used for the Imagecreation

    # OS
    $OsLayerId = (Get-ALOsLayer -websession $websessionPROD | Where-Object {$(($ImageLayersDEV | Where-Object {$ImportedEqualLayerDetails.guid -like $_.guid}).BaseName) -eq $_.name})
    $OsRevs = (Get-ALOsLayerDetail -websession $websessionPROD -id $OsLayerId.id).Revisions.OsLayerRevisionDetail
    $OsRevId = ($OsRevs | Where-Object {$ImageLayersDEV.Guid -like $_.Guid.ToUpper()})

    # Platform
    $PlatFormLayerId = (Get-ALPlatformlayer -websession $websessionPROD | Where-Object {$(($ImageLayersDEV | Where-Object {$ImportedEqualLayerDetails.guid -like $_.guid}).BaseName) -eq $_.name})
    $PlatFormRevs = (Get-ALPlatformLayerDetail -websession $websessionPROD -id $PlatFormLayerId.id).Revisions.PlatformLayerRevisionDetail
    $PlatFormRevId = ($PlatFormRevs | Where-Object {$ImageLayersDEV.Guid -like $_.Guid.ToUpper()})

    # App
    $AppLayerId = (Get-ALapplayer -websession $websessionPROD | Where-Object {$(($ImageLayersDEV | Where-Object {$ImportedEqualLayerDetails.guid -like $_.guid}).BaseName) -eq $_.name})
    $AppRevs = ($AppLayerId | ForEach-Object{Get-ALapplayerDetail -websession $websessionPROD -id $_.id}).Revisions.AppLayerRevisionDetail
    $AppRevIds = ($AppRevs | Where-Object {$ImageLayersDEV.Guid -like $_.Guid.ToUpper()})

    # Create new Image
    Write-Host "$(Write-TimeNumberSign) Create new Image" -ForegroundColor Yellow
    Logaction "Create new Image"
    $connector = Get-ALconnector -websession $websessionPROD -type Publish | Where-Object{$_.name -eq $HVConnectorProd}

    # Define Parameters to create the image on the production side.
    $params = @{
    websession = $websessionPROD;
    name =  $ImageDEV.Name;
    osrevid = $OsRevId.id;
    platrevid = $PlatFormRevId.id;
    description = $ImageDEV.Name;
    connectorid = $connector.id;
    diskformat = $connector.ValidDiskFormats.DiskFormat;
    appids = $AppRevIds.id;
    size = $ImageDEV.SizeMB;
    ElasticLayerMode = $imageDEV.ElasticLayerMode
    }

    # reconnect
    $websessionPROD = Connect-alsession -aplip $approdlip -Credential $Credential

    # Define new image name for PROD Appliance
    $ImageProdName = $($ImageDEV.Name.Replace('_DTA_','_PROD_'))
    
    # Image creation on the PROD Appliance
    # Replace when exist otherwise create it
    $imageexists = Get-ALimage -websession $websessionPROD | Where-Object{$_.name -eq $ImageProdName}
    if ($imageexists -eq $null)
    {
        Write-Host "$(Write-TimeIndent) Image does not yet exist. Creating..." -ForegroundColor Yellow
        Logaction "Image does not yet exist. Creating..."
        Try{New-alimage @params -OutVariable NewAlImage -ea stop -Confirm:$false | Out-Null
            Write-Host "$(Write-TimeIndent) New-alimage [$ImageProdName] Succeeded" -ForegroundColor Green
            }Catch [Exception] {Write-Host "$(Write-TimeIndent) FAILED - New-alimage [$ImageProdName] - $_" -ForegroundColor RED}
    } 
    else
    {
        Write-Host "$(Write-TimeIndent) Image already exist. Replacing..." -ForegroundColor Yellow
        Try{Remove-ALImage -websession $websessionPROD -id $imageexists.Id  -ea stop -Confirm:$false | Out-Null
            Write-Host "$(Write-TimeIndent) Remove-alimage [$ImageProdName] Succeeded" -ForegroundColor Green
            } Catch [Exception] {Write-Host "$(Write-TimeIndent) FAILED - Remove-alimage [$ImageProdName] - $_"  -ForegroundColor RED}
        Try{New-alimage @params -OutVariable NewAlImage -ea stop -Confirm:$false | Out-Null
            Write-Host "$(Write-TimeIndent) New-alimage [$ImageProdName] Succeeded" -ForegroundColor Green
            }Catch [Exception] {Write-Host "$(Write-TimeIndent) FAILED - New-alimage [$ImageProdName] - $_" -ForegroundColor RED}
    }
    # Get-Status and loop while task status is running
    $NewAlImageStatus = Get-ALStatus -id $NewAlImage -websession $websessionPROD

    $a = 0
    Do {
    IF ($a -eq "99") {$a=0}
    if (($NewAlImageStatus.Status -notlike "Running") -and ($NewAlImageStatus.Status -notlike "Pending")){
        $a=100
		Write-Progress -Activity "Create Image Done" -PercentComplete $a -Status "Finish."
		Start-Sleep 1
		Write-Progress "Done" "Done" -completed	
		break
	} ELSE {
        $NewAlImageStatus = Get-ALStatus -id $NewAlImage -websession $websessionPROD
        $a++
		Write-Progress -Activity "Creating Image is in [$($NewAlImageStatus.Status)] state, waiting until finished..." -PercentComplete $a -Status "Please wait..."
        start-sleep 5
        }
    } While ($a -ne 100)

    Write-Host "$(Write-TimeIndent) FINISHED Image creation" -ForegroundColor Green
    Logaction "FINISHED Image creation"

    # Get Image Composition
    $imagesPROD = Get-ALImageComp -websession $websessionPROD | Where-Object {$_.name -eq $ImageProdName}

    foreach ($imagePROD in $imagesPROD)
    {
    
        # Create an new array including the Layer Name, id, revision, guid, status and priority. these property names are constant accross the import/export commandlets
        # the layer guid is retrieved being an unique layer identifier for comparision across appliances while the layer ID is unique with a specific appliance context. 
        $ImageLayersPROD = [System.Collections.ArrayList]@()
        $ImageLayersPROD += $ImagePROD.OSLayer | ForEach-Object{[pscustomobject]@{BaseName = $($_.Name).toupper();RevName = $($_.VersionNAME).toupper();ID = $($_.ID).toupper();Priority = $null;Status = $($_.Status).toupper();Guid = $($OsRevId.Guid).toupper();Type = $($OsLayerId.Type)}}
        $ImageLayersPROD += $ImagePROD.PlatformLayer | ForEach-Object{[pscustomobject]@{BaseName = $($_.Name).toupper();RevName = $($_.VersionNAME).toupper();ID = $($_.ID).toupper();Priority = $null;Status = $($_.Status).toupper();;Guid = $($PlatFormRevId.Guid).toupper();Type = $($PlatFormLayerId.Type)}}
        $ImageLayersPROD += $ImagePROD.AppLayer | ForEach-Object{$i = 0}{[pscustomobject]@{BaseName = $($_.Name).toupper();RevName = $($_.VersionNAME).toupper();ID = $($_.ID).toupper();Priority = $($_.Priority).toupper();Status = $($_.Status).toupper();Guid = $($ImportedEqualLayerDetails | Where-Object {$_.id -like $ImagePROD.applayer[$i].Id}).Guid.toupper();Type = $($AppLayerId[$i].Type)};$i++}

        # Show created table
        Write-Host "$(Write-TimeIndent) Image Layers Composition Exported" -ForegroundColor Yellow
        $ImageLayersDEV | Sort-Object Priority -Descending | Format-Table -AutoSize

        Write-Host "$(Write-TimeIndent) Image Layers Composition Imported" -ForegroundColor Yellow
        $ImageLayersPROD | Sort-Object Priority -Descending | Format-Table -AutoSize

        # Publish image when the attribute was provided.
        if ($publish -eq "YES")
        {
            Write-Host "$(Write-TimeNumberSign ) publish property set for [$($imagetopublish.name)]" -ForegroundColor yellow
            Logaction "publish property set for [$($imagetopublish.name)]"
            $imagetopublish = Get-ALImage -websession $websessionPROD | Where-Object {$_.name -eq $ImageProdName}
            Write-Host "$(Write-Timeindent ) publishing image [$($imagetopublish.name)] with id: [$($imagetopublish.id)]" -ForegroundColor yellow
            Logaction "publishing image [$($imagetopublish.name)] with id: [$($imagetopublish.id)]"

            # Publish the image
            $invokealpublish = invoke-alpublish -websession $websessionPROD -imageid $($imagetopublish).id -Outvariable invokealpublish -Confirm:$false
                         
            # Get-Status and loop while task status is running
            $invokealpublishStatus = Get-ALStatus -id $invokealpublish -websession $websessionPROD

                $a = 0
                Do {
                IF ($a -eq "99") {$a=0}
                if (($invokealpublishStatus.Status -notlike "Running") -and ($invokealpublishStatus.Status -notlike "Pending")){
                    $a=100
                    Write-Progress -Activity "Publishing image [$($imagetopublish.name)] done " -PercentComplete $a -Status "Finish."
                    Start-Sleep 1
                    Write-Progress "Done" "Done" -completed	
                    break
                } ELSE {
                    $invokealpublishStatus = Get-ALStatus -id $invokealpublish -websession $websessionPROD
                    $a++
                    Write-Progress -Activity "Publishing image [$($imagetopublish.name)] running, waiting until finished..." -PercentComplete $a -Status "Please wait..."
                    start-sleep 5
                    }
                } While ($a -ne 100)

            Write-Host "$(Write-TimeIndent) FINISHED publish" -ForegroundColor Green
            Logaction "FINISHED publish"      
        
        } else {Write-Host "$(Write-TimeNumberSign) publish image property was not set for [$($imagetopublish.name)]" -ForegroundColor Yellow}

    } # END Foreach ImagesProd

} # END Foreach ImagesDev

# Exported laypkg files on export/import Share
Write-Host "$(Write-TimeNumberSign) Cleanup obsolete Layers Exports under [$($mypath)\Unidesk\Exported Layers]" -ForegroundColor Yellow
Logaction "Cleanup obsolete Layers Exports under [$($mypath)\Unidesk\Exported Layers]"      
    
# Find all laypkg files and delete all but the last '$skiplast' number of files.
$OSLaypkg = GCi "$mypath\Unidesk\Exported Layers\$($ImageDEV.OsLayer.NAME)" -File | where {$_.Name -match "^\d*[S_]\w*[.]\w*(.laypkg)"} | Sort-Object { $_.Name.Split('_')[1]} | Select-Object -SkipLast $Skiplast | Remove-Item -Confirm:$false
$LaypkgFolders = GCi "$mypath\Unidesk\Exported Layers\$($ImageDEV.OsLayer.NAME)" -Directory | % { Get-ChildItem "$($_.fullname)" | where {$_.Name -match "^\w*[.]\w*(.laypkg)"} | Sort-Object { $_.Name.Split('_')[1]} | Select-Object -SkipLast $Skiplast | Remove-Item -Confirm:$false}

# Remove empty Folders
$LaypkgFolders  | % { if(!(gci -Path $_.FullName)) {Remove-Item -Force -Recurse $_.FullName} }

# DisConnect from Appliances
disconnect-alsession -websession $websessionDEV
disconnect-alsession -websession $websessionPROD
###
Write-Host "$(Write-TimeNumberSign) *** READY ***" -ForegroundColor Green
Logaction "*** READY ***"     

