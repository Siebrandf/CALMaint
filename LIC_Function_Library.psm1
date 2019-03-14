<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>

# FUNCTIONS ---------------------

function Show-ProgressBar{
	<#
    .SYNOPSIS
        show Powershell ProgressBar
	.Description
      	Show Powershell Progressbar to see something is working in the background, it checks an active process
		use get-help <functionname> -full to see full help
	.PARAMETER CheckProcess
        A process object to pass to the function. This can be retrieved with "Get-Process" and stored as a variable
    .PARAMETER CheckProcessId
        A process ID that the function will check against.
    .PARAMETER ActivityText
        Text that describes what the progress bar is waiting on.
    .PARAMETER MaximumExecutionMinutes
        The amount of time in minutes that the function will wait before continuing.
    .PARAMETER TerminateRunawayProcess
        If the maximum execution time is exceeded this switch will foricbly terminate the process.
	.EXAMPLE
		Show-BISFProgressbar
    .Inputs
    .Outputs
    .NOTES
		Author: Matthias Schlimm
      	Company: Login Consultants Germany GmbH

		History
      	Last Change: dd.mm.yyyy MS: function created
		Last Change: 28.06.2017 MS: add .SYNOPSIS to this function
		Last Change: 22.06.2017 FF: add ProgressID to this function to use it instead of ProgressName only
	    Last Change: 31.08.2017 MS: POSH Progressbar, sleep time during preparation only
		Last Change: 05.09.2017 TT: Added Maximum Execution Minutes and Terminate Runaway Process parameters
	.Link
#>
    PARAM(
		[parameter()][string]$CheckProcess,
        [parameter()][int]$CheckProcessId,
		[parameter(Mandatory=$True)][string]$ActivityText,
		[parameter()][int]$MaximumExecutionMinutes,
        [parameter()][switch]$TerminateRunawayProcess
	)
    $a=0
	if ($MaximumExecutionMinutes) {
		$MaximumExecutionTime = (Get-Date).AddMinutes($MaximumExecutionMinutes)
	} ELSE {
        $MaximumExecutionMinutes = 60
        $MaximumExecutionTime = (Get-Date).AddMinutes($MaximumExecutionMinutes)
    }
	Start-Sleep 5
    for ($a=0; $a -lt 100; $a++) {
		IF ($a -eq "99") {$a=0}
		If ($CheckProcessId)
		{
			$ProcessActive = Get-Process -Id $CheckProcessId -ErrorAction SilentlyContinue
		} else {
			$ProcessActive = Get-Process $CheckProcess -ErrorAction SilentlyContinue
		}
		#$ProcessActive = Get-Process $CheckProcess -ErrorAction SilentlyContinue  #26.07.2017 MS: comment-out:

        if ((Get-Date) -ge $MaximumExecutionTime) {
			Write-BISFLog -Msg "The operation has exceeded the maximum execution time of $MaximumExecutionMinutes Minutes." -Type W
            if ($TerminateRunawayProcess) {
                Write-BISFLog -Msg "Forcibly terminating process. $($ProcessActive.Name)" -Type W
			    Stop-Process $ProcessActive -Force -ErrorAction SilentlyContinue
                Clear-Variable -Name "ProcessActive"
            }
            else {
                Clear-Variable -Name "ProcessActive" #this nulls out the variable allowing the "finish" bar
            }
		}

	   	if($ProcessActive -eq $null) {
           	$a=100
           	Write-Progress -Activity "Finish...wait for next operation in 5 seconds" -PercentComplete $a -Status "Finish."
           	IF ($State -eq "Preparation") {Start-Sleep 5}
            Write-Progress "Done" "Done" -completed
            break
       	} else {
            Start-Sleep 1
            $display= "{0:N2}" -f $a #reduce display to 2 digits on the right side of the numeric
            Write-Progress -Activity "$ActivityText" -PercentComplete $a -Status "Please wait..."
       	}
    }
}

function Write-TimeIndent
{
    "`t[$((Get-Date).ToString("HH:mm:ss"))] >"
}

function Write-TimeNumberSign
{
    "[$((Get-Date).ToString("HH:mm:ss"))] #"
}

Function Get-PendingReboot {
    # Reset variables
    $PendingCBSReboot = $False
    $PendingWUAUReboot = $False
    $PendingDomainJoin = $False
    $PendingMachineRename = $False
    $PendingFileRename = $False
 
    # Making registry connection to the local computer
	$HKLM = [UInt32] "0x80000002"
	$WMI_Reg = [WMIClass] "\\localhost\root\default:StdRegProv"
 
    # Get build information
    $WMI_OS = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber, CSName -ComputerName "localhost" -ErrorAction Stop
 
    # Query Component Based Services registry key
	If ([Int32]$WMI_OS.BuildNumber -ge 6001) {
		$RegSubKeysCBS = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")
		$PendingCBSReboot = $RegSubKeysCBS.sNames -contains "RebootPending"
	}
 
    # Query Windows Update for pending reboot
	$PendingWUAURebootReg = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
	$PendingWUAUReboot = $PendingWUAURebootReg.sNames -contains "RebootRequired"
 
    # Query PendingFileRenameOperations registry key
	$RegSubKeySM = $WMI_Reg.GetMultiStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\Session Manager\","PendingFileRenameOperations")
	$RegValuePFRO = $RegSubKeySM.sValue
	If ($RegValuePFRO) {
		$PendingFileRename = $True
	}
 
    # Query JoinDomain registry key
	$Netlogon = $WMI_Reg.EnumKey($HKLM,"SYSTEM\CurrentControlSet\Services\Netlogon").sNames
	$PendingDomainJoin = ($Netlogon -contains 'JoinDomain') -or ($Netlogon -contains 'AvoidSpnSet')
 
    # Query ComputerName and ActiveComputerName registry keys and compare
	$ActCompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\","ComputerName")
	$CompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\","ComputerName")
 
	If (($ActCompNm -ne $CompNm) -or $PendingDomainJoin) {
	    $PendingMachineRename = $true
	}
 
    # Convert to a single true or false and return results
    $RebootPending = ($PendingCBSReboot -or $PendingWUAUReboot -or $PendingDomainJoin -or $PendingMachineRename -or $PendingFileRename)
 
    $RebootPendingResults = "`t[$((Get-Date).ToString("HH:mm:ss"))] > Reboot needed: $RebootPending"
    Return $RebootPendingResults
}

function Write-ProgressHelper
{
   param (
      [int]$StepNumber,

      [string]$Message
   )
Write-Progress -Activity 'Title' -Status $Message -PercentComplete (($StepNumber / $steps) * 100)
}

Function Set-Owner {
    <#
        .SYNOPSIS
            Changes owner of a file or folder to another user or group.

        .DESCRIPTION
            Changes owner of a file or folder to another user or group.

        .PARAMETER Path
            The folder or file that will have the owner changed.

        .PARAMETER Account
            Optional parameter to change owner of a file or folder to specified account.

            Default value is 'Builtin\Administrators'

        .PARAMETER Recurse
            Recursively set ownership on subfolders and files beneath given folder.

        .NOTES
            Name: Set-Owner
            Author: Boe Prox
            Version History:
                 1.0 - Boe Prox
                    - Initial Version

        .EXAMPLE
            Set-Owner -Path C:\temp\test.txt

            Description
            -----------
            Changes the owner of test.txt to Builtin\Administrators

        .EXAMPLE
            Set-Owner -Path C:\temp\test.txt -Account 'Domain\bprox

            Description
            -----------
            Changes the owner of test.txt to Domain\bprox

        .EXAMPLE
            Set-Owner -Path C:\temp -Recurse 

            Description
            -----------
            Changes the owner of all files and folders under C:\Temp to Builtin\Administrators

        .EXAMPLE
            Get-ChildItem C:\Temp | Set-Owner -Recurse -Account 'Domain\bprox'

            Description
            -----------
            Changes the owner of all files and folders under C:\Temp to Domain\bprox
    #>
    [cmdletbinding(
        SupportsShouldProcess = $True
    )]
    Param (
        [parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [Alias('FullName')]
        [string[]]$Path = "C:\Windows\Temp",
        [parameter()]
        [string]$Account = 'Builtin\Administrators',
        [parameter()]
        [switch]$Recurse
    )
    Begin {
        #Prevent Confirmation on each Write-Debug command when using -Debug
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }
        Try {
            [void][TokenAdjuster]
        } Catch {
            $AdjustTokenPrivileges = @"
            using System;
            using System.Runtime.InteropServices;

             public class TokenAdjuster
             {
              [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
              internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
              ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
              [DllImport("kernel32.dll", ExactSpelling = true)]
              internal static extern IntPtr GetCurrentProcess();
              [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
              internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr
              phtok);
              [DllImport("advapi32.dll", SetLastError = true)]
              internal static extern bool LookupPrivilegeValue(string host, string name,
              ref long pluid);
              [StructLayout(LayoutKind.Sequential, Pack = 1)]
              internal struct TokPriv1Luid
              {
               public int Count;
               public long Luid;
               public int Attr;
              }
              internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
              internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
              internal const int TOKEN_QUERY = 0x00000008;
              internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
              public static bool AddPrivilege(string privilege)
              {
               try
               {
                bool retVal;
                TokPriv1Luid tp;
                IntPtr hproc = GetCurrentProcess();
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
                tp.Count = 1;
                tp.Luid = 0;
                tp.Attr = SE_PRIVILEGE_ENABLED;
                retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
                retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                return retVal;
               }
               catch (Exception ex)
               {
                throw ex;
               }
              }
              public static bool RemovePrivilege(string privilege)
              {
               try
               {
                bool retVal;
                TokPriv1Luid tp;
                IntPtr hproc = GetCurrentProcess();
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
                tp.Count = 1;
                tp.Luid = 0;
                tp.Attr = SE_PRIVILEGE_DISABLED;
                retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
                retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                return retVal;
               }
               catch (Exception ex)
               {
                throw ex;
               }
              }
             }
"@
            Add-Type $AdjustTokenPrivileges
        }

        #Activate necessary admin privileges to make changes without NTFS perms
        [void][TokenAdjuster]::AddPrivilege("SeRestorePrivilege") #Necessary to set Owner Permissions
        [void][TokenAdjuster]::AddPrivilege("SeBackupPrivilege") #Necessary to bypass Traverse Checking
        [void][TokenAdjuster]::AddPrivilege("SeTakeOwnershipPrivilege") #Necessary to override FilePermissions
    }
    Process {
        ForEach ($Item in $Path) {
            Write-Verbose "FullName: $Item"
            #The ACL objects do not like being used more than once, so re-create them on the Process block
            $DirOwner = New-Object System.Security.AccessControl.DirectorySecurity
            $DirOwner.SetOwner([System.Security.Principal.NTAccount]$Account)
            $FileOwner = New-Object System.Security.AccessControl.FileSecurity
            $FileOwner.SetOwner([System.Security.Principal.NTAccount]$Account)
            $DirAdminAcl = New-Object System.Security.AccessControl.DirectorySecurity
            $FileAdminAcl = New-Object System.Security.AccessControl.DirectorySecurity
            $AdminACL = New-Object System.Security.AccessControl.FileSystemAccessRule('Builtin\Administrators','FullControl','ContainerInherit,ObjectInherit','InheritOnly','Allow')
            $FileAdminAcl.AddAccessRule($AdminACL)
            $DirAdminAcl.AddAccessRule($AdminACL)
            Try {
                $Item = Get-Item -LiteralPath $Item -Force -ErrorAction Stop
                If (-NOT $Item.PSIsContainer) {
                    If ($PSCmdlet.ShouldProcess($Item, 'Set File Owner')) {
                        Try {
                            $Item.SetAccessControl($FileOwner)
                        } Catch {
                            Write-Warning "Couldn't take ownership of $($Item.FullName)! Taking FullControl of $($Item.Directory.FullName)"
                            $Item.Directory.SetAccessControl($FileAdminAcl)
                            $Item.SetAccessControl($FileOwner)
                        }
                    }
                } Else {
                    If ($PSCmdlet.ShouldProcess($Item, 'Set Directory Owner')) {                        
                        Try {
                            $Item.SetAccessControl($DirOwner)
                        } Catch {
                            Write-Warning "Couldn't take ownership of $($Item.FullName)! Taking FullControl of $($Item.Parent.FullName)"
                            $Item.Parent.SetAccessControl($DirAdminAcl) 
                            $Item.SetAccessControl($DirOwner)
                        }
                    }
                    If ($Recurse) {
                        [void]$PSBoundParameters.Remove('Path')
                        Get-ChildItem $Item -Force | Set-Owner @PSBoundParameters
                    }
                }
            } Catch {
                Write-Warning "$($Item): $($_.Exception.Message)"
            }
        }
    }
    End {  
        #Remove priviledges that had been granted
        [void][TokenAdjuster]::RemovePrivilege("SeRestorePrivilege") 
        [void][TokenAdjuster]::RemovePrivilege("SeBackupPrivilege") 
        [void][TokenAdjuster]::RemovePrivilege("SeTakeOwnershipPrivilege")     
    }
}

Function Invoke-WUInstall
{
    <# 
 .SYNOPSIS 
  Invoke Get-WUInstall remotely. 
 
 .DESCRIPTION 
  Use Invoke-WUInstall to invoke Windows Update install remotly. It Based on TaskScheduler because 
  CreateUpdateDownloader() and CreateUpdateInstaller() methods can't be called from a remote computer - E_ACCESSDENIED. 
   
  Note: 
  Because we do not have the ability to interact, is recommended use -AcceptAll with WUInstall filters in script block. 
  
 .PARAMETER ComputerName 
  Specify computer name. 
 
 .PARAMETER TaskName 
  Specify task name. Default is PSWindowsUpdate. 
 
 .PARAMETER TaskStart 
  Specify task start datetime. 
 
 .PARAMETER RunNow 
  Run task start immediately. 
   
 .PARAMETER Script 
  Specify PowerShell script block that you what to run. Default is {ipmo PSWindowsUpdate; Get-WUInstall -AcceptAll | Out-File C:\PSWindowsUpdate.log} 
   
 .PARAMETER SkipModuleTest 
        Skip module testing on destination. 
 
 .PARAMETER Credential 
        Alternate Credential. 
 
 .EXAMPLE 
  PS C:\> $Script = {ipmo PSWindowsUpdate; Get-WUInstall -AcceptAll -AutoReboot | Out-File C:\PSWindowsUpdate.log} 
  PS C:\> Invoke-WUInstall -ComputerName pc1.contoso.com -Script $Script 
  ... 
  PS C:\> Get-Content \\pc1.contoso.com\c$\PSWindowsUpdate.log 
   
 .EXAMPLE 
        PS C:\> Invoke-WUInstall -ComputerName 10.10.10.10 -TaskStart (Get-Date).AddMinutes(10).ToString() -Credential (Get-Credential .\Administrator) -Verbose -SkipModuleTest 
 
 .NOTES 
  Author: Michal Gajda 
  Blog : http://commandlinegeeks.com/ 
 
 .LINK 
  Get-WUInstall 
 #>
    [CmdletBinding(
        SupportsShouldProcess=$True,
        ConfirmImpact="High"
    )]
    param
    (
        [Parameter(ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$True)]
        [String[]]$ComputerName,
        [String]$TaskName = "PSWindowsUpdate",
        [DateTime]$TaskStart,
        [Switch]$RunNow,
        [Switch]$SkipModuleTest,
        [ScriptBlock]$Script = {ipmo PSWindowsUpdate; Get-WUInstall -AcceptAll | Out-File C:\PSWindowsUpdate.log},
        [Switch]$OnlineUpdate,
        [PSCredential]$Credential
    )

    Begin
    {
        $User = [Security.Principal.WindowsIdentity]::GetCurrent()
        $Role = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

        if($Credential)
        {
            $UserName = ($Credential.GetNetworkCredential()).UserName
            $Domain = ($Credential.GetNetworkCredential()).Domain
            $Password = ($Credential.GetNetworkCredential()).Password
        }

        if(!$Role)
        {
            Write-Warning "To perform some operations you must run an elevated Windows PowerShell console."    
        } #End If !$Role
        
        $PSWUModule = Get-Module -Name PSWindowsUpdate -ListAvailable
        
        Write-Verbose "Create schedule service object"
        $Scheduler = New-Object -ComObject Schedule.Service
            
        $Task = $Scheduler.NewTask(0)

        $RegistrationInfo = $Task.RegistrationInfo
        $RegistrationInfo.Description = $TaskName
        $RegistrationInfo.Author = $User.Name

        $Settings = $Task.Settings
        $Settings.Enabled = $True
        $Settings.StartWhenAvailable = $True
        $Settings.Hidden = $False

        $Action = $Task.Actions.Create(0)
        $Action.Path = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        $Action.Arguments = "-Command $Script"
        
        if($TaskStart)
        {
            $Trigger = $Task.Triggers.Create(1)
            $Trigger.StartBoundary = $TaskStart.ToString("yyyy-MM-ddTHH:mm:ss") 
        } #End if($TaskStart)

        $Task.Principal.RunLevel = 1    
    }
    
    Process
    {
        ForEach($Computer in $ComputerName)
        {
            If ($pscmdlet.ShouldProcess($Computer,"Invoke WUInstall")) 
            {
                if(Get-WmiObject -Class Win32_PingStatus -Filter "Address='$Computer' AND Timeout=1000")
                {
                    if(!$SkipModuleTest)
                    {
                        Write-Verbose "Check PSWindowsUpdate module on $Computer"
                        Try
                        {
                            if($Credential)
                            {
                                $ModuleTest = Invoke-Command -ComputerName $Computer -Credential $Credential -ScriptBlock {Get-Module -ListAvailable -Name PSWindowsUpdate} -ErrorAction Stop 
                            } else
                            {
                                $ModuleTest = Invoke-Command -ComputerName $Computer -ScriptBlock {Get-Module -ListAvailable -Name PSWindowsUpdate} -ErrorAction Stop
                            }
                        } #End Try
                        Catch
                        {
                            Write-Warning "Can't access to machine $Computer. Try use: winrm qc"
                            Continue
                        } #End Catch
                        $ModulStatus = $false
                    
                        if($ModuleTest -eq $null -or $ModuleTest.Version -lt $PSWUModule.Version)
                        {
                            if($OnlineUpdate)
                            {
                                Update-WUModule -ComputerName $Computer
                            } #End If $OnlineUpdate
                            else
                            {
                                Update-WUModule -ComputerName $Computer    -LocalPSWUSource (Get-Module -ListAvailable -Name PSWindowsUpdate).ModuleBase
                            } #End Else $OnlineUpdate
                        } #End If $ModuleTest -eq $null -or $ModuleTest.Version -lt $PSWUModule.Version
                    }

                    #Sometimes can't connect at first time
                    $Info = "Connect to scheduler and register task on $Computer"
                    for ($i=1; $i -le 3; $i++)
                    {
                        $Info += "."
                        Write-Verbose $Info
                        Try
                        {
                            if($Credential)    
                            {                        
                                $Scheduler.Connect($Computer,$UserName,$Domain,$Password)
                            } else
                            {
                                $Scheduler.Connect($Computer)
                            }
                            Break
                        } #End Try
                        Catch
                        {
                            if($i -ge 3)
                            {
                                Write-Error "Can't connect to Schedule service on $Computer" -ErrorAction Stop
                            } #End If $i -ge 3
                            else
                            {
                                sleep -Seconds 1
                            } #End Else $i -ge 3
                        } #End Catch                    
                    } #End For $i=1; $i -le 3; $i++
                    
                    $RootFolder = $Scheduler.GetFolder("\")
                    $SendFlag = 1
                    if($Scheduler.GetRunningTasks(0) | Where-Object {$_.Name -eq $TaskName})
                    {
                        $CurrentTask = $RootFolder.GetTask($TaskName)
                        $Title = "Task $TaskName is curretly running: $($CurrentTask.Definition.Actions | Select-Object -exp Path) $($CurrentTask.Definition.Actions | Select-Object -exp Arguments)"
                        $Message = "What do you want to do?"

                        $ChoiceContiniue = New-Object System.Management.Automation.Host.ChoiceDescription "&Continue Current Task"
                        $ChoiceStart = New-Object System.Management.Automation.Host.ChoiceDescription "Stop and Start &New Task"
                        $ChoiceStop = New-Object System.Management.Automation.Host.ChoiceDescription "&Stop Task"
                        $Options = [System.Management.Automation.Host.ChoiceDescription[]]($ChoiceContiniue, $ChoiceStart, $ChoiceStop)
                        $SendFlag = $host.ui.PromptForChoice($Title, $Message, $Options, 0)
                    
                        if($SendFlag -ge 1)
                        {
                            ($RootFolder.GetTask($TaskName)).Stop(0)
                        } #End If $SendFlag -eq 1    
                        
                    } #End If !($Scheduler.GetRunningTasks(0) | Where-Object {$_.Name -eq $TaskName})
                        
                    if($SendFlag -eq 1)
                    {
                        $RootFolder.RegisterTaskDefinition($TaskName, $Task, 6, "SYSTEM", $Null, 1) | Out-Null
                        if($RunNow)
                        {
                            $RootFolder.GetTask($TaskName).Run(0) | Out-Null
                        } #End if($RunNow)
                    } #End If $SendFlag -eq 1
                    
                    #$RootFolder.DeleteTask($TaskName,0)
                } #End If Test-Connection -ComputerName $Computer -Quiet
                else
                {
                    Write-Warning "Machine $Computer is not responding."
                } #End Else Test-Connection -ComputerName $Computer -Quiet
            } #End If $pscmdlet.ShouldProcess($Computer,"Invoke WUInstall")
        } #End ForEach $Computer in $ComputerName
        Write-Verbose "Invoke-WUInstall complete."
    }
    
    End {}

}

function LogMe() {
Param(
[parameter(Mandatory = $true, ValueFromPipeline = $true)] $logEntry,
[switch]$display,
[switch]$error,
[switch]$WARNING,
[switch]$progress
)  
    if ($error) { $logEntry = "[ERROR] $logEntry" ; Write-Host "$logEntry" -Foregroundcolor Red }
    elseif ($WARNING) { Write-WARNING "$logEntry" ; $logEntry = "[WARNING] $logEntry" }
    elseif ($progress) { Write-Host "$logEntry" -Foregroundcolor Green }
    elseif ($display) { Write-Host "$logEntry" }
}

#heavily based on https://gallery.technet.microsoft.com/scriptcenter/Verify-the-Active-021eedea/view/Discussions#content
function Test-ADCredential {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]$Credential
    )
    begin {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    }
    process {
        if (!($Credential.UserName) -or !($Credential.GetNetworkCredential().Password)) {
            Write-Warning 'Test-ADCredential: Please specify both user name and password'
        } else 
        {
            $Domain = $Credential.GetNetworkCredential().Domain 
            $ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain 
            $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext $ct,$Domain 
            $DS.ValidateCredentials($Credential.UserName,$Credential.GetNetworkCredential().Password)
        }
    }
}


#Clear User Info Function
    Function ClearUserInfo
    {
        $Cred = $Null
        $DomainNetBIOS = $Null
        $UserName  = $Null
        $Password = $Null
    }

#Rerun The Script Function
 Function Rerun
    {
        $Title = "Test Another Credentials?"
        $Message = "Do you want to Test Another Credentials?"
        $Yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Test Another Credentials."
        $No = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "End Script."
        $Options = [System.Management.Automation.Host.ChoiceDescription[]]($Yes, $No)
        $Result = $host.ui.PromptForChoice($Title, $Message, $Options, 0) 

        Switch ($Result)
        {
            0 {TestUserCredentials}
            1 {"End Script."}
        }
    }

#Test User Credentials Function
Function TestUserCredentials
{
    ClearUserInfo   
    #Get user credentials
    $Cred = Get-Credential -Message "Enter Your Credentials (Domain\Username)"
    if ($Cred -eq $Null)
                        {
                            Write-Host "Please enter your username in the form of Domain\UserName and try again" -BackgroundColor Black -ForegroundColor Yellow
                            Rerun
                            Break                          
                        }

    #Parse provided user credentials
    $DomainNetBIOS = $Cred.username.Split("{\}")[0]
    $UserName = $Cred.username.Split("{\}")[1]
    $Password = $Cred.GetNetworkCredential().password
    
    Write-Host "`n"
    Write-Host "Checking Credentials for $DomainNetBIOS\$UserName" -BackgroundColor Black -ForegroundColor White
    Write-Host "***************************************"

    If ($DomainNetBIOS -eq $Null -or $UserName -eq $Null) 
                        {
                            Write-Host "Please enter your username in the form of Domain\UserName and try again" -BackgroundColor Black -ForegroundColor Yellow
                            Rerun
                            Break
                        }
    #    Checks if the domain in question is reachable, and get the domain FQDN.
    Try
    {
        $DomainFQDN = (Get-ADDomain $DomainNetBIOS).DNSRoot
    }
    Catch
    {
        Write-Host "Error: Domain was not found: " $_.Exception.Message -BackgroundColor Black -ForegroundColor Red
        Write-Host "Please make sure the domain NetBios name is correct, and is reachable from this computer" -BackgroundColor Black -ForegroundColor Red
        Rerun
        Break
    }
    
    #Checks user credentials against the domain
    $DomainObj = "LDAP://" + $DomainFQDN
    $DomainBind = New-Object System.DirectoryServices.DirectoryEntry($DomainObj,$UserName,$Password)
    $DomainName = $DomainBind.distinguishedName
    
    If ($DomainName -eq $Null)
        {
            Write-Host "Domain $DomainFQDN was found: True" -BackgroundColor Black -ForegroundColor Green
        
            $UserExist = Get-ADUser -Server $DomainFQDN -Properties LockedOut -Filter {sAMAccountName -eq $UserName}
            If ($UserExist -eq $Null) 
                        {
                            Write-Host "Error: Username $Username does not exist in $DomainFQDN Domain." -BackgroundColor Black -ForegroundColor Red
                            Rerun
                            Break
                        }
            Else 
                        {   
                            Write-Host "User exists in the domain: True" -BackgroundColor Black -ForegroundColor Green


                            If ($UserExist.Enabled -eq "True")
                                    {
                                        Write-Host "User Enabled: "$UserExist.Enabled -BackgroundColor Black -ForegroundColor Green
                                    }

                            Else
                                    {
                                        Write-Host "User Enabled: "$UserExist.Enabled -BackgroundColor Black -ForegroundColor RED
                                        Write-Host "Enable the user account in Active Directory, Then check again" -BackgroundColor Black -ForegroundColor RED
                                        Rerun
                                        Break
                                    }

                            If ($UserExist.LockedOut -eq "True")
                                    {
                                        Write-Host "User Locked: " $UserExist.LockedOut -BackgroundColor Black -ForegroundColor Red
                                        Write-Host "Unlock the User Account in Active Directory, Then check again..." -BackgroundColor Black -ForegroundColor RED
                                        Rerun
                                        Break
                                    }
                            Else
                                    {
                                        Write-Host "User Locked: " $UserExist.LockedOut -BackgroundColor Black -ForegroundColor Green
                                    }
                        }
    
            Write-Host "Authentication failed for $DomainNetBIOS\$UserName with the provided password." -BackgroundColor Black -ForegroundColor Red
            Write-Host "Please confirm the password, and try again..." -BackgroundColor Black -ForegroundColor Red
            Rerun
            Break
        }
     
    Else
        {
        Write-Host "SUCCESS: The account $Username successfully authenticated against the domain: $DomainFQDN" -BackgroundColor Black -ForegroundColor Green
        Rerun
        Break
        }
}    

function WaitUntilServices($searchString)
{
    # Get all services where DisplayName matches $searchString and loop through each of them.
    foreach($service in (Get-Service -Name $searchString))
    {
        # Wait for the service to reach the $status or a maximum of 30 seconds
        $service.WaitForStatus("Running", '00:00:59')
    }
}

function Test-Ping([string]$hostname) {
    
    $retry = $null;$result = $null
        
    do {
            $retry+=1; $result = get-wmiobject -Query "select * from win32_pingstatus where Address='$hostname'"
            if ($result.StatusCode -eq 0){"Ping [$($hostname.ToUpper())] [$($result.statuscode)] with Responsetime [$($result.responsetime)]"  | LogMe -display -progress}
            if ($result.statuscode -ne 0){"Ping [$($hostname.ToUpper())] [$($result.statuscode)] NOT Successfull" | LogMe -display -progress; Sleep 5}

     } until (($retry -eq "3") -or ($result.StatusCode -eq 0))
         if ($retry -eq "3")
         {
            Write-Host "three failed Attempt to ping [$hostname]" -ForegroundColor Red
         }

         return $result
}

function Get-RunningTask
{
    <# 
    .Synopsis 
        Gets the tasks currently running on the system 
    .Description 
        A Detailed Description of what the command does 
    .Example 
        Get-RunningTask 
    #>
    param(
    #The name of the task. By default, all running tasks are shown
    $Name = "*",

    # If this is set, hidden tasks will also be shown. 
    # By default, only tasks that are not marked by Task Scheduler as hidden are shown.
    [Switch]
    $Hidden,    
    
    # The name of the computer to connect to.
    $ComputerName,
    
    # The credential used to connect
    [Management.Automation.PSCredential]
    $Credential
    )        
    
    process {
        $scheduler = Connect-ToTaskScheduler -ComputerName $ComputerName -Credential $Credential        
        if ($scheduler -and $scheduler.Connected) {
            $scheduler.GetRunningTasks($Hidden -as [bool]) | Where-Object { 
                $_.Name -like $Name -or 
                (Split-Path $_.Path -Leaf) -like $name
            }
        }
    }    
} 

function Connect-ToTaskScheduler
{
    <# 
    .Synopsis 
        Connects to the scheduler service on a computer 
    .Description 
        Connects to the scheduler service on a computer 
    .Example 
        Connect-ToTaskScheduler 
    #>
    param(
    # The name of the computer to connect to.
    $ComputerName,
    
    # The credential used to connect
    [Management.Automation.PSCredential]
    $Credential    
    )   
    
    $scheduler = New-Object -ComObject Schedule.Service
    if ($Credential) { 
        $NetworkCredential = $Credential.GetNetworkCredential()
        $scheduler.Connect($ComputerName, 
            $NetworkCredential.UserName, 
            $NetworkCredential.Domain, 
            $NetworkCredential.Password)            
    } else {
        $scheduler.Connect($ComputerName)        
    }    
    $scheduler
}

function Test-BuilVMWSMan
{
    <# 
    .Synopsis 
        Test if machine is reacheable
    .Description 
        A Detailed Description of what the command does 
    .Example 
        Test-BuilVMWSMan -computerName *** -Credential *** -ValidationState UP
    #>
    param(
    # The name of the computer to connect to.
    [parameter(Mandatory=$true)]
    $ComputerName,
    # The credential used to connect
    [Management.Automation.PSCredential]
    [parameter(Mandatory=$true)]
    $Credential,
    # The name of the computer to connect to.
    [parameter(Mandatory=$true)]
    [ValidateSet("Down", "Up")]
    $ValidationState
    )  
    
    # Test if machine is reacheable
    $ALBuildVMTestWSMAN = Test-WSMan -ComputerName $ComputerName -Credential $Credential -Authentication Default -ea SilentlyContinu
    $a = 0

    if ($ValidationState -eq "UP"){
        Do {
            IF ($a -eq "99") {$a=0}
            if ($ALBuildVMTestWSMAN.ProductVendor -eq "Microsoft Corporation"){
                $a=100
			    Write-Progress -Activity "WinRM service is responding..." -PercentComplete $a -Status "Finish."
			    Start-Sleep 5
			    Write-Progress "Done" "Done" -completed	
			    break
		    } ELSE {
                $ALBuildVMTestWSMAN = Test-WSMan -ComputerName $ComputerName -Credential $Credential -Authentication Default -ea SilentlyContinue    
		        $a++
		        Write-Progress -Activity "Verify WinRM service is responding..." -PercentComplete $a -Status "Please wait...$a %"
                start-sleep 5
                }
        } While ($a -ne 100)
        ###
        Write-Host "$(Write-TimeIndent) Machine [$ComputerName] is reacheable...." -ForegroundColor Green    
    } # End if ($ValidationState -eq "UP")

    if ($ValidationState -eq "DOWN"){
        Do {
            IF ($a -eq "99") {$a=0}
            if ($ALBuildVMTestWSMAN.ProductVendor -ne "Microsoft Corporation"){
                $a=100
			    Write-Progress -Activity " WinRM service is no longer responding..." -PercentComplete $a -Status "Finish."
			    Start-Sleep 1
			    Write-Progress "Done" "Done" -completed	
			    break
		    } ELSE {
                $ALBuildVMTestWSMAN = Test-WSMan -ComputerName $ComputerName -Credential $Credential -Authentication Default -ea SilentlyContinue
                $a++
		        Write-Progress -Activity "Verify WinRM service is no longer responding..." -PercentComplete $a -Status "Please wait...$a %"
                # Write-Host "." -NoNewline -ForegroundColor Yellow
                start-sleep 1
                }
        } While ($a -ne 100)
        ###
        Write-Host "$(Write-TimeIndent) Machine [$ComputerName] is down...." -ForegroundColor Green
    } # End if ($ValidationState -eq "DOWN")

}

function Set-RemoteRegistry 
{
<#
	.SYNOPSIS
		Set-RemoteRegistry allows user to set any given registry key/value pair.

	.DESCRIPTION
		Set-RemoteRegistry allows user to change registry on remote computer using remote registry access.

	.PARAMETER  ComputerName
		Computer name where registry change is desired. If not specified, defaults to computer where script is run.

	.PARAMETER  Hive
		Registry hive where the desired key exists. If no value is specified, LocalMachine is used as default value. Valid values are: ClassesRoot,CurrentConfig,CurrentUser,DynData,LocalMachine,PerformanceData and Users.

	.PARAMETER  Key
		Key where item value needs to be created/changed. Specify Key in the following format: System\CurrentControlSet\Services.

	.PARAMETER  Name
		Name of the item that needs to be created/changed.
		
	.PARAMETER  Value
		Value of item that needs to be created/changed. Value must be of correct type (as specified by -Type).
		
	.PARAMETER  Type
		Type of item being created/changed. Valid values for type are: String,ExpandString,Binary,DWord,MultiString and QWord.
		
	.PARAMETER  Force
		Allows user to bypass confirmation prompts.
		
	.EXAMPLE
		PS C:\> .\Set-RemoteRegistry.ps1 -Key SYSTEM\CurrentControlSet\services\AudioSrv\Parameters -Name ServiceDllUnloadOnStop -Value 1 -Type DWord

	.EXAMPLE
		PS C:\> .\Set-RemoteRegistry.ps1 -ComputerName ServerA -Key SYSTEM\CurrentControlSet\services\AudioSrv\Parameters -Name ServiceDllUnloadOnStop -Value 0 -Type DWord -Force

	.INPUTS
		System.String

	.OUTPUTS
		System.String

	.NOTES
		Created and maintainted by Bhargav Shukla (MSFT). Please report errors through contact form at http://blogs.technet.com/b/bshukla/contact.aspx. Do not remove original author credits or reference.

	.LINK
		http://blogs.technet.com/bshukla
#>
	[CmdletBinding(SupportsShouldProcess=$true)]
	param
	(
		[Parameter(Position=0, Mandatory=$false)]
		[System.String]
		$ComputerName = $Env:COMPUTERNAME,
		[Parameter(Position=1, Mandatory=$false)]
		[ValidateSet("ClassesRoot","CurrentConfig","CurrentUser","DynData","LocalMachine","PerformanceData","Users")]
		[System.String]
		$Hive = "LocalMachine",
		[Parameter(Position=2, Mandatory=$true, HelpMessage="Enter Registry key in format System\CurrentControlSet\Services")]
		[ValidateNotNullOrEmpty()]
		[System.String]
		$Key,
		[Parameter(Position=3, Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[System.String]
		$Name,
		[Parameter(Position=4, Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[System.String]
		$Value,		
		[Parameter(Position=5, Mandatory=$true)]
		[ValidateSet("String","ExpandString","Binary","DWord","MultiString","QWord")]
		[System.String]
		$Type,
		[Parameter(Position=6, Mandatory=$false)]
		[Switch]
		$Force
	)
	
	If ($pscmdlet.ShouldProcess($ComputerName, "Open registry $Hive"))
	{
	#Open remote registry
	try
	{
			$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($Hive, $ComputerName)
		
	}
	catch 
	{
		Write-Error "The computer $ComputerName is inaccessible. Please check computer name. Please ensure remote registry service is running and you have administrative access to $ComputerName."
		Return
	}
	}

	If ($pscmdlet.ShouldProcess($ComputerName, "Check existense of $Key"))
	{
	#Open the targeted remote registry key/subkey as read/write
	$regKey = $reg.OpenSubKey($Key,$true)
		
	#Since trying to open a regkey doesn't error for non-existent key, let's sanity check
	#Create subkey if parent exists. If not, exit.
	If ($regkey -eq $null)
	{	
		Write-Warning "Specified key $Key does not exist in $Hive."
		$Key -match ".*\x5C" | Out-Null
		$parentKey = $matches[0]
		$Key -match ".*\x5C(\w*\z)" | Out-Null
		$childKey = $matches[1]

		try
		{
			$regtemp = $reg.OpenSubKey($parentKey,$true)
		}
		catch
		{
			Write-Error "$parentKey doesn't exist in $Hive or you don't have access to it. Exiting."
			Return
		}
		If ($regtemp -ne $null)
		{
			Write-Output "$parentKey exists. Creating $childKey in $parentKey."
			try
			{
				$regtemp.CreateSubKey($childKey) | Out-Null
			}
			catch 
			{
				Write-Error "Could not create $childKey in $parentKey. You  may not have permission. Exiting."
				Return
			}

			$regKey = $reg.OpenSubKey($Key,$true)
		}
		else
		{
			Write-Error "$parentKey doesn't exist. Exiting."
			Return
		}
	}
	
	#Cleanup temp operations
	try
	{
		$regtemp.close()
		Remove-Variable $regtemp,$parentKey,$childKey
	}
	catch
	{
		#Nothing to do here. Just suppressing the error if $regtemp was null
	}
	}
	
	#If we got this far, we have the key, create or update values
	If ($Force)
	{
		If ($pscmdlet.ShouldProcess($ComputerName, "Create or change $Name's value to $Value in $Key. Since -Force is in use, no confirmation needed from user"))
		{
			$regKey.Setvalue("$Name", "$Value", "$Type")
		}
	}
	else
	{
		If ($pscmdlet.ShouldProcess($ComputerName, "Create or change $Name's value to $Value in $Key. No -Force specified, user will be asked for confirmation"))
		{
		$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes",""
		$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No",""
		$choices = [System.Management.Automation.Host.ChoiceDescription[]]($yes,$no)
		$caption = "Warning!"
		$message = "Value of $Name will be set to $Value. Current value `(If any`) will be replaced. Do you want to proceed?"
		Switch ($result = $Host.UI.PromptForChoice($caption,$message,$choices,0))
		{
			1
			{
				Return
			}
			0
			{
				$regKey.Setvalue("$Name", "$Value", "$Type")
			}
		}
		}
	}
	
	#Cleanup all variables
	try
	{
		$regKey.close()
		Remove-Variable $ComputerName,$Hive,$Key,$Name,$Value,$Force,$reg,$regKey,$yes,$no,$caption,$message,$result
	}
	catch
	{
		#Nothing to do here. Just suppressing the error if any variable is null
	}

}

Function Pause ($Message = "Press any key to continue...") {
   # Check if running in PowerShell ISE
   If ($psISE) {
      # "ReadKey" not supported in PowerShell ISE.
      # Show MessageBox UI
      $Shell = New-Object -ComObject "WScript.Shell"
      $Button = $Shell.Popup("Click OK to continue.", 0, "Hello", 0)
      Return
   }

   $Ignore =
      16,  # Shift (left or right)
      17,  # Ctrl (left or right)
      18,  # Alt (left or right)
      20,  # Caps lock
      91,  # Windows key (left)
      92,  # Windows key (right)
      93,  # Menu key
      144, # Num lock
      145, # Scroll lock
      166, # Back
      167, # Forward
      168, # Refresh
      169, # Stop
      170, # Search
      171, # Favorites
      172, # Start/Home
      173, # Mute
      174, # Volume Down
      175, # Volume Up
      176, # Next Track
      177, # Previous Track
      178, # Stop Media
      179, # Play
      180, # Mail
      181, # Select Media
      182, # Application 1
      183  # Application 2

   Write-Host -NoNewline $Message
   While ($KeyInfo.VirtualKeyCode -Eq $Null -Or $Ignore -Contains $KeyInfo.VirtualKeyCode) {
      $KeyInfo = $Host.UI.RawUI.ReadKey("NoEcho, IncludeKeyDown")
   }
}