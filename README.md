# CALMaint
Citrix Application Layering Maintenance and Houskeeping

# Citrix App Layering Appliance Houskeeping 
Based on the Citrix App Layering PowerShell SDK

These scripts are based and dependant on a reversed engineered SDK that communicates with the CAL Applicance using SOAP calls.
Currently only supports version **4.11 or later**.  **THIS USES UNSUPPORTED API CALLS.  PLEASE USE WITH CAUTION.**

Source 'Reverse Engineered SDK to manage the Citrix App Layering appliance' https://github.com/ryancbutler/UnideskSDK

- [Citrix App Layering PowerShell SDK (BETA)](#citrix-app-layering-powershell-sdk--beta-)
  * [Install and Update](#install-and-update)
    + [Install Manually](#install-manually)
    + [Install PSGallery](#install-psgallery)
    + [Update PSGallery](#update-psgallery)
  * [Cleanup Obsolete Images](#Cleanup-Obsolete-Images)
  * [Cleanup Obsolete Revisions](#Cleanup-Obsolete-Revisions)
  * [Clone Images to different appliance](#Clone-Obsolete-Revisions)
  * [Publish Image(s)](#Publish-Images)
  * [Update Image(s)](#Update-Images)
  * [Function Library](#Function-Library)
  * [Images2Process Json](#Images2Process-Json)
  

## Install and Update

### Install Manually

```powershell
Import-Module ".\ctxal-sdk.psm1"
```

### Install PSGallery

```powershell
Find-Module -name ctxal-sdk
Install-Module -Name ctxal-sdk -Scope CurrentUser/AllUsers
```

### Update PSGallery

```powershell
Find-Module -name ctxal-sdk
Update-Module -Name ctxal-sdk
```

## Cleanup Obsolete Images
```
NAME
    CAL_PowerShell_SDK_Cleanup_Obsolete_Images.ps1

SYNOPSIS
    Cleanup Images per ‘unique role’ and ‘revision number’ on the layering appliance skipping the last three (by default)
```
```powershell
SYNTAX
    CAL_PowerShell_SDK_Cleanup_Obsolete_Images.ps1 [-Environment {DTA|PROD}] [-Credential <$credential>]
```
```
PARAMETERS
    -Environment <string>
        The environment parameter let you choose between two appliance environments.
        Valid values are DTA and PROD
        Required?                    True
    
    -Credential <pscredential>
        Connection credentials for the layering appliance. Either provide a PSCredential object or an username
        Required?                    True
```

## Cleanup Obsolete Revisions
```
NAME
    CAL_PowerShell_SDK_Cleanup_Obsolete_Revisions.ps1

SYNOPSIS
    Cleanup layer revision based on type (OS, App and Platform) name and ‘revision number’ on the layering appliance. 
    Remove all layers not currently being assigned except the two having the highest revision number and not being assigned.
```
```powershell
SYNTAX
    CAL_PowerShell_SDK_Cleanup_Obsolete_Revisions.ps1 [-LayerType {OSLayer|AppLayer|PlatformLayer}] [-Environment {DTA|PROD}] [-Credential <pscredential>] [-Whatif]
```
```
PARAMETERS
    -LayerType <string>
        Provide the Layer type to process.
        Valid values are OsLayer, PlatformLayer, AppLayer
        Required?                    True

    -Environment <string>
        Provide the Environment to process.
        Valid values are DTA, Prod
        Required?                    True
    
    -Credential <pscredential>
        Connection credentials for the layering appliance. Either provide a PSCredential object or an username
        Required?                    True
```

## Clone Images to different appliance
```
NAME
    CAL_PowerShell_SDK_Clone_Image.ps1

SYNOPSIS
    Clone existing image(s) from the DTA appliance to the Prod Applicance using a (multi-select) gridview selection window. 
    It also provides a argument to publish the image from the prod appliance after import. One at the time.
    The ‘inputpath’ variable can be used to provide the path to the ‘Images4$environment.json file which includes ‘ImageReference’ attribute 
    which clones the highest image revisions automatically.
```
```powershell
SYNTAX
    CAL_PowerShell_SDK_Clone_Image.ps1 [-publish {NO|YES}] [-Credential <pscredential>] [-inputpath <pathtojson>]
```
```
PARAMETERS
    -Publish <string>
        Provide the Environment to process.
        Valid values are NO, YES
        Required?                    false
        Default                      NO
    
    -Inputpath <string>
        Provide the path to the 'Images4$Environment.json' file containing the references names for the images to export.
        Valid values are NO, YES
        Required?                    false

    -Credential <pscredential>
        Connection credentials for the layering appliance. Either provide a PSCredential object or an username
        Required?                    True
```

## Publish Images
```
NAME
    CAL_PowerShell_SDK_Publish_Image.ps1

SYNOPSIS
    Publish image{s} from the appliance. These jobs are executed in parallel. 
    The ‘inputpath’ variable can be used to provide the path to the ‘Images4$environment.json’ file which includes an attribute for 
    ‘ImageReference’ which trigger publishing of the latest image revisions for the given references automatically. 
    The ‘Images4$environment.json’ is updated during execution with the ImageId and ImageName of the Images being published.
```
```powershell
SYNTAX
    CAL_PowerShell_SDK_Publish_Image.ps1 [-Environment {DTA|PROD}] [-Credential <pscredential>] [-Inputpath UNCpathtojsonfile]
```
```
PARAMETERS
    -Environment <string>
        Provide the Environment to process.
        Valid values are DTA, Prod
        Required?                    True
    
    -Inputpath <string>
        Provide the path to the 'Images4$Environment.json' file containing the references names for the images to export.
        Valid values are NO, YES
        Required?                    false

    -Credential <pscredential>
        Connection credentials for the layering appliance. Either provide a PSCredential object or an username
        Required?                    True
```

## Update Images
```
NAME
    CAL_PowerShell_SDK_Update_Images.ps1

SYNOPSIS
    Verifies if the latest revision for all existing image(s) based on their unique ‘role name’ have the latest OS, Platform and predefined App Layer revisions. If not, the images will be cloned with an increased revision number including the latest changes. 
```
```powershell
SYNTAX
    CAL_PowerShell_SDK_Update_Images.ps1 [-Environment {DTA|PROD}] [-Credential <pscredential>]
```
```
PARAMETERS
    -Environment <string>
        Provide the Environment to process.
        Valid values are DTA, Prod
        Required?                    True
    
    -Credential <pscredential>
        Connection credentials for the layering appliance. Either provide a PSCredential object or an username
        Required?                    True
```

## Function Library
```
NAME
    LIC_Function_Library.psm1

SYNOPSIS
    Includes generic often used functions which can be called from various scripts.

EXAMPLE
    The following scriptlet example can be used for import-module. 

NOTES
    Make sure the LIC_Function_Library.psm1 is in the same folder as the script which calls it.
```
```powershell
function Get-ScriptDirectory {
    if ($psise) {Split-Path $psise.CurrentFile.FullPath}
    else {Split-Path $script:MyInvocation.MyCommand.Path}
}

# MODULES -----------------------
Import-Module "$(Get-ScriptDirectory)\LIC_Function_Library.psm1" -DisableNameChecking
```

## Images2Process Json
```
NAME
    Images4$Environment.json

SYNOPSIS
    The file below is an example of an Image4$environment json file used as optional input for clone, and publishing and update catalog activities where $environment represent the environment which is provided trough command line. Which can either be DTA, DEV, ACC or PROD. 
    'CAL_PowerShell_SDK_Publish_Image.ps1' Updates the json file with the id and name for the highest available revision for a given referencename. 
```
```json
[
    {
        "Catalog":  "MCSCatalogName",
        "ImageReference":  "R_W10_DSK_IMG_",
        "ImageName":  "R_W10_DSK_IMG_R009",
        "id":  "13467726",
        "StorageResource":  "MCSStorageResourceName"
    },
    {
        "Catalog":  "MCSCatalogName",
        "ImageReference":  "R_W10_SAP_IMG_",
        "ImageName":  "R_W10_SAP_IMG_R077",
        "id":  "14581763",
        "StorageResource":  "MCSStorageResourceName"
    }
]
```