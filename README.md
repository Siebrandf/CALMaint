# CALMaint
Citrix Application Layering Maintenance

# Citrix App Layering Appliance Houskeeping based on the Citrix App Layering PowerShell SDK

This script is based on a reversed engineered SDK that emulates the SOAP calls that AL uses to manage the appliance.
Currently only supports version **4.11 or later**.  **THIS USES UNSUPPORTED API CALLS.  PLEASE USE WITH CAUTION.**

Source 'Reverse Engineered SDK to manage the Citrix App Layering appliance' https://github.com/ryancbutler/UnideskSDK

- [Citrix App Layering PowerShell SDK (BETA)](#citrix-app-layering-powershell-sdk--beta-)
  * [Install and Update](#install-and-update)
    + [Install Manually](#install-manually)
    + [Install PSGallery](#install-psgallery)
    + [Update PSGallery](#update-psgallery)
  * [Script Operation](#Script-Operation)

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

## Script Operation

NAME
    CAL_PowerShell_SDK_Cleanup_Obsolete_Revisions.ps1

SYNTAX
    CAL_PowerShell_SDK_Cleanup_Obsolete_Revisions.ps1 [-LayerType] <LayerType> [-Environment] <Environment> [-Skiplast] <Int32> [-Confirm] [-Whatif]

PARAMETERS
    -LayerType <LayerType>
        Provide the Layer type to process.
        Valid values are OsLayer, PlatformLayer, AppLayer
        Required?                    True

    -Environment <Environment>
        Provide the Environment to process.
        Valid values are DTA, Prod
        Required?                    True

    -Skiplast <Int32>
        Provide the number of revision to keep other than the ones currently in use
        Default                      2   
        Required?                    false

    -Confirm
        Required?                    false


EXAMPLES

------------------------- EXAMPLE 1 --------------------------

    C:\PS> CAL_PowerShell_SDK_Cleanup_Obsolete_Revisions.ps1 -LayerType AppLayer -Environment DTA -Confirm:$false

    Description

    -----------

    The two last revisions older than the ones associated for the DTA appliance are deleted without confirmation