# CALMaint
Citrix Application Layering Maintenance

# Citrix App Layering Appliance Houskeeping 
Based on the Citrix App Layering PowerShell SDK

This script is based on a reversed engineered SDK that emulates the SOAP calls that AL uses to manage the appliance.
Currently only supports version **4.11 or later**.  **THIS USES UNSUPPORTED API CALLS.  PLEASE USE WITH CAUTION.**

Source 'Reverse Engineered SDK to manage the Citrix App Layering appliance' https://github.com/ryancbutler/UnideskSDK

- [Citrix App Layering PowerShell SDK (BETA)](#citrix-app-layering-powershell-sdk--beta-)
  * [Install and Update](#install-and-update)
    + [Install Manually](#install-manually)
    + [Install PSGallery](#install-psgallery)
    + [Update PSGallery](#update-psgallery)
- [CAL_PowerShell_SDK_Cleanup_Obsolete_Images.ps1](#CAL_PowerShell_SDK_Cleanup_Obsolete_Images)

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

## CAL_PowerShell_SDK_Cleanup_Obsolete_Images.ps1
```powershell
NAME
    CAL_PowerShell_SDK_Cleanup_Obsolete_Images.ps1

DESCRIPTION
    Cleanup Images per ‘unique role’ and ‘revision number’ on the layering appliance skipping the last three (by default)

SYNTAX
    CAL_PowerShell_SDK_Cleanup_Obsolete_Images.ps1 [-Environment {DTA|PROD}] [-Credential <$credential>]

PARAMETERS
    -Environment <string>
        The environment parameter let you choose between two appliance environments.
        Valid values are DTA and PROD
        Required?                    True
    
    -Credential <pscredential>
        Either provide a PSCredential object or a username
        Required?                    True
```

## CAL_PowerShell_SDK_Cleanup_Obsolete_Revisions.ps1
```powershell
NAME
    CAL_PowerShell_SDK_Cleanup_Obsolete_Revisions.ps1

DESCRIPTION
    Cleanup layer revision based on type (OS, App and Platform) name and ‘revision number’ on the layering appliance. 
    Remove all layers not currently being assigned except the two having the highest revision number and not being assigned

SYNTAX
    CAL_PowerShell_SDK_Cleanup_Obsolete_Revisions.ps1 [-LayerType {OSLayer|AppLayer|PlatformLayer}] [-Environment {DTA|PROD}] [-Credential <pscredential>] [-Whatif]

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
        Either provide a PSCredential object or a username
        Required?                    True
```