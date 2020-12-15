<#
.SYNOPSIS
    Download and install all configured modules within the Intune Notification framework from an Azure Storage Account container.

.DESCRIPTION
    Download and install all configured modules within the Intune Notification framework from an Azure Storage Account container.

.PARAMETER StorageAccountName
    Name of the Azure storage account where the notification framework files can be accessed.

.PARAMETER ContainerName
    Name of the container within the storage account where the notification framework files can be accessed.

.PARAMETER CompanyName
    Company name that will be used for creating a root directory where the notification framework will be installed within.

.PARAMETER InstallPath
    Construct the full path for where the notification framework will be installed.

.EXAMPLE
    .\Install-NotificationFramework.ps1

.NOTES
    FileName:    Install-NotificationFramework.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2020-12-02
    Updated:     2020-12-02

    Version history:
    1.0.0 - (2020-12-02) Script created
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [parameter(Mandatory = $false, HelpMessage = "Name of the Azure storage account where the notification framework files can be accessed.")]
    [ValidateNotNullOrEmpty()]
    [string]$StorageAccountName = "scconfigmgrappdata",

    [parameter(Mandatory = $false, HelpMessage = "Name of the container within the storage account where the notification framework files can be accessed.")]
    [ValidateNotNullOrEmpty()]
    [string]$ContainerName = "intune-notification",

    [parameter(Mandatory = $false, HelpMessage = "Company name that will be used for creating a root directory where the notification framework will be installed within.")]
    [ValidateNotNullOrEmpty()]
    [string]$CompanyName = "MSEndpointMgr",

    [parameter(Mandatory = $false, HelpMessage = "Construct the full path for where the notification framework will be installed.")]
    [ValidateNotNullOrEmpty()]
    [string]$InstallPath = "$($env:ProgramData)\$($CompanyName)\NotificationFramework"
)
Begin {
    # Install required modules for script execution
    $Modules = @("Az.Storage", "Az.Resources")
    foreach ($Module in $Modules) {
        try {
            $CurrentModule = Get-InstalledModule -Name $Module -ErrorAction Stop -Verbose:$false
            if ($CurrentModule -ne $null) {
                $LatestModuleVersion = (Find-Module -Name $Module -ErrorAction Stop -Verbose:$false).Version
                if ($LatestModuleVersion -gt $CurrentModule.Version) {
                    $UpdateModuleInvocation = Update-Module -Name $Module -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
                }
            }
        }
        catch [System.Exception] {
            try {
                # Install NuGet package provider
                $PackageProvider = Install-PackageProvider -Name NuGet -Force -Verbose:$false
        
                # Install current missing module
                Install-Module -Name $Module -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
            }
            catch [System.Exception] {
                Write-Warning -Message "An error occurred while attempting to install $($Module) module. Error message: $($_.Exception.Message)"
            }
        }
    }

    # Retrieve storage account context
    $StorageAccountContext = New-AzStorageContext -StorageAccountName $StorageAccountName -Anonymous -ErrorAction Stop

    # Create install directory if it doesn't exist
    if (-not(Test-Path -Path $InstallPath)) {
        New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
    }

    # Create modules directory if it doesn't exist
    $ModulesPath = Join-Path -Path $InstallPath -ChildPath "Modules"
    if (-not(Test-Path -Path $ModulesPath)) {
        New-Item -Path $ModulesPath -ItemType Directory -Force | Out-Null
    }
}
Process {
    # Functions
    function Write-LogEntry {
        param (
            [parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
            [ValidateNotNullOrEmpty()]
            [string]$Value,
    
            [parameter(Mandatory = $true, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
            [ValidateNotNullOrEmpty()]
            [ValidateSet("1", "2", "3")]
            [string]$Severity,
    
            [parameter(Mandatory = $false, HelpMessage = "Name of the log file that the entry will written to.")]
            [ValidateNotNullOrEmpty()]
            [string]$FileName = "IntuneNotificationFramework.log"
        )
        # Determine log file location
        $LogFilePath = Join-Path -Path (Join-Path -Path $env:windir -ChildPath "Temp") -ChildPath $FileName
        
        # Construct time stamp for log entry
        $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), "+", (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
        
        # Construct date for log entry
        $Date = (Get-Date -Format "MM-dd-yyyy")
        
        # Construct context for log entry
        $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        
        # Construct final log entry
        $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""IntuneNotificationFramework"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
        
        # Add value to log file
        try {
            Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message "Unable to append log entry to IntuneNotificationFramework.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
    }

    function Get-AzureStorageContainerContent {
        param(
            [parameter(Mandatory = $true, HelpMessage = "Name of the Azure storage account.")]
            [ValidateNotNullOrEmpty()]
            [string]$StorageAccountName,
    
            [parameter(Mandatory = $true, HelpMessage = "Name of the Azure storage blob or container.")]
            [ValidateNotNullOrEmpty()]
            [string]$ContainerName
        )
        try {   
            # Construct array list for return value containing file names
            $ContainerContentList = New-Object -TypeName System.Collections.ArrayList
    
            try {
                # Retrieve content from storage account blob
                $StorageContainerContents = Get-AzStorageBlob -Container $ContainerName -Context $StorageAccountContext -ErrorAction Stop
                if ($StorageContainerContents -ne $null) {
                    foreach ($StorageContainerContent in $StorageContainerContents) {
                        Write-LogEntry -Value "Adding content file from Azure storage container to return list: $($StorageContainerContent.Name)" -Severity 1
                        $ContainerContentList.Add($StorageContainerContent) | Out-Null
                    }
                }
    
                # Handle return value
                return $ContainerContentList
            }
            catch [System.Exception] {
                Write-LogEntry -Value "Failed to retrieve storage account container contents. Error message: $($_.Exception.Message)" -Severity 3
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value "Failed to retrieve storage account context. Error message: $($_.Exception.Message)" -Severity 3
        }
    }

    function Invoke-AzureStorageContainerContentDownload {
        param(
            [parameter(Mandatory = $true, HelpMessage = "Name of the Azure storage blob or container.")]
            [ValidateNotNullOrEmpty()]
            [string]$ContainerName,

            [parameter(Mandatory = $true, HelpMessage = "Name of the file in the Azure storage blob or container.")]
            [ValidateNotNullOrEmpty()]
            [string]$FileName,

            [parameter(Mandatory = $true, HelpMessage = "Download destination directory path for the file.")]
            [ValidateNotNullOrEmpty()]
            [string]$Destination
        )        
        try {
            # Download default wallpaper content file from storage account
            Write-LogEntry -Value "Downloading content file from Azure storage container: $($FileName)" -Severity 1
            $StorageBlobContent = Get-AzStorageBlobContent -Container $ContainerName -Blob $FileName -Context $StorageAccountContext -Destination $Destination -Force -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-LogEntry -Value "Failed to download '$($FileName)' content from Azure storage container. Error message: $($_.Exception.Message)" -Severity 3
        }
    }

    function New-ToastNotificationApp {
        param(
            [parameter(Mandatory = $true, HelpMessage = "Specify the ID of the notification app, e.g. 'Company.Notification'.")]
            [ValidateNotNullOrEmpty()]
            [string]$ID,
    
            [parameter(Mandatory = $true, HelpMessage = "Specify the display name of the notification app, e.g. 'Company Notification'.")]
            [ValidateNotNullOrEmpty()]
            [string]$DisplayName,
            
            [parameter(Mandatory = $false, HelpMessage = "Define whether the notification app should be configurable within Settings app, for notifications to be turned On or Off. Supported values are: 0 = Off, 1 = On.")]
            [ValidateNotNullOrEmpty()]
            [int]$ShowInSettings = 0,
    
            [parameter(Mandatory = $false, HelpMessage = "Specify the full path including filename of the icon used for the notification app. System environment variables are supported.")]
            [ValidateNotNullOrEmpty()]
            [string]$IconUri = "%SystemRoot%\ImmersiveControlPanel\images\logo.png"
        )
        Process {
            # Attempt to retrieve HKEY_CLASSES_ROOT hive
            $HKCRDrive = Get-PSDrive -Name "HKCR" -ErrorAction SilentlyContinue

            try {
                # Mount the HKEY_CLASSES_ROOT hive drive if not already available
                if ($HKCRDrive -eq $null) {
                    New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Scope "Script" -ErrorAction Stop | Out-Null
                }

                # Define the registry path variables necessary
                $AppUserModelIDPath = Join-Path -Path "HKCR:\" -ChildPath "AppUserModelId"
                $AppIDPath = Join-Path -Path $AppUserModelIDPath -ChildPath $ID

                # Create registry key for given AppID passed as parameter input
                if (-not(Test-Path -Path $AppIDPath)) {
                    New-Item -Path $AppUserModelIDPath -Name $ID -Force | Out-Null
                }

                # Check if DisplayName value exists that matches parameter input, it doesn't exist create the value, if it exist but the value doesn't match, amend it
                $DisplayNameValue = Get-ItemProperty -Path $AppIDPath -Name "DisplayName" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisplayName"
                if ($DisplayNameValue -ne $DisplayName) {
                    New-ItemProperty -Path $AppIDPath -Name "DisplayName" -Value $DisplayName -PropertyType "String" -Force | Out-Null
                }

                # Check if ShowInSettings value exists that matches parameter input, it doesn't exist create the value, if it exist but the value doesn't match, amend it
                $ShowInSettingsValue = Get-ItemProperty -Path $AppIDPath -Name "ShowInSettings" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "ShowInSettings"
                if ($ShowInSettingsValue -ne $ShowInSettings) {
                    New-ItemProperty -Path $AppIDPath -Name "ShowInSettings" -Value $ShowInSettings -PropertyType "DWORD" -Force | Out-Null
                }

                # Check if IconUri value exists that matches parameter input, it doesn't exist create the value, if it exist but the value doesn't match, amend it
                $IconUriValue = Get-ItemProperty -Path $AppIDPath -Name "IconUri" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "IconUri"
                if ($IconUriValue -ne $IconUri) {
                    New-ItemProperty -Path $AppIDPath -Name "IconUri" -Value $IconUri -PropertyType "ExpandString" -Force | Out-Null
                }
            }
            catch [System.Exception] {
                Write-LogEntry -Value "Failed to load HKEY_CLASSES_ROOT hive. Error message: $($_.Exception.Message)" -Severity 3; break
            }
        }
        End {
            # Dismount the HKEY_CLASSES_ROOT hive drive
            $HKCRDrive = Get-PSDrive -Name "HKCR" -ErrorAction SilentlyContinue
            if ($HKCRDrive -ne $null) {
                Remove-PSDrive -Name "HKCR" -Force
            }
        }
    }

    function New-NotificationScheduledTask {
        param(
            [parameter(Mandatory = $true, ParameterSetName = "Interval", HelpMessage = ".")]
            [parameter(Mandatory = $true, ParameterSetName = "Daily")]
            [parameter(Mandatory = $true, ParameterSetName = "Hourly")]
            [parameter(Mandatory = $true, ParameterSetName = "Minutes")]
            [switch]$Interval,
    
            [parameter(Mandatory = $true, ParameterSetName = "Event", HelpMessage = ".")]
            [switch]$Event,
    
            [parameter(Mandatory = $true, ParameterSetName = "Daily", HelpMessage = ".")]
            [switch]$Daily,
    
            [parameter(Mandatory = $true, ParameterSetName = "Hourly", HelpMessage = ".")]
            [switch]$Hourly,
    
            [parameter(Mandatory = $true, ParameterSetName = "Minutes", HelpMessage = ".")]
            [switch]$Minutes,
    
            [parameter(Mandatory = $true, ParameterSetName = "Event", HelpMessage = ".")]
            [ValidateNotNullOrEmpty()]
            [ValidateSet("AtWorkstationUnlock", "AtLogon", "AtStartup")]
            [string[]]$Trigger,
    
            [parameter(Mandatory = $true, ParameterSetName = "Interval", HelpMessage = ".")]
            [parameter(Mandatory = $true, ParameterSetName = "Daily")]
            [parameter(Mandatory = $true, ParameterSetName = "Hourly")]
            [parameter(Mandatory = $true, ParameterSetName = "Minutes")]
            [ValidateNotNullOrEmpty()]
            [int]$Frequency,
    
            [parameter(Mandatory = $false, ParameterSetName = "Interval", HelpMessage = ".")]
            [parameter(Mandatory = $true, ParameterSetName = "Daily")]
            [ValidateNotNullOrEmpty()]
            [datetime]$Time,
    
            [parameter(Mandatory = $true, ParameterSetName = "Interval", HelpMessage = ".")]
            [parameter(Mandatory = $true, ParameterSetName = "Daily")]
            [parameter(Mandatory = $true, ParameterSetName = "Hourly")]
            [parameter(Mandatory = $true, ParameterSetName = "Minutes")]
            [parameter(Mandatory = $true, ParameterSetName = "Event")]
            [ValidateNotNullOrEmpty()]
            [string]$Name,

            [parameter(Mandatory = $true, ParameterSetName = "Interval", HelpMessage = ".")]
            [parameter(Mandatory = $true, ParameterSetName = "Daily")]
            [parameter(Mandatory = $true, ParameterSetName = "Hourly")]
            [parameter(Mandatory = $true, ParameterSetName = "Minutes")]
            [parameter(Mandatory = $true, ParameterSetName = "Event")]
            [ValidateNotNullOrEmpty()]
            [string]$Path,
    
            [parameter(Mandatory = $true, ParameterSetName = "Interval", HelpMessage = ".")]
            [parameter(Mandatory = $true, ParameterSetName = "Daily")]
            [parameter(Mandatory = $true, ParameterSetName = "Hourly")]
            [parameter(Mandatory = $true, ParameterSetName = "Minutes")]
            [parameter(Mandatory = $true, ParameterSetName = "Event")]
            [ValidateNotNullOrEmpty()]
            [string]$ProcessName,
    
            [parameter(Mandatory = $true, ParameterSetName = "Interval", HelpMessage = ".")]
            [parameter(Mandatory = $true, ParameterSetName = "Daily")]
            [parameter(Mandatory = $true, ParameterSetName = "Hourly")]
            [parameter(Mandatory = $true, ParameterSetName = "Minutes")]
            [parameter(Mandatory = $true, ParameterSetName = "Event")]
            [ValidateNotNullOrEmpty()]
            [string]$Arguments,
    
            [parameter(Mandatory = $true, ParameterSetName = "Interval", HelpMessage = ".")]
            [parameter(Mandatory = $true, ParameterSetName = "Daily")]
            [parameter(Mandatory = $true, ParameterSetName = "Hourly")]
            [parameter(Mandatory = $true, ParameterSetName = "Minutes")]
            [parameter(Mandatory = $true, ParameterSetName = "Event")]
            [ValidateNotNullOrEmpty()]
            [ValidateSet("System", "User")]
            [string]$Principal
        )
        Process {
            try {
                # Construct scheduled task action
                $TaskAction = New-ScheduledTaskAction -Execute $ProcessName -Argument $Arguments -ErrorAction Stop
    
                # Construct the scheduled task principal
                switch ($Principal) {
                    "System" {
                        $TaskPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType "ServiceAccount" -RunLevel "Highest" -ErrorAction Stop
                    }
                    "User" {
                        $TaskPrincipal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users" -RunLevel "Highest" -ErrorAction
                    }
                }
    
                # Construct array list for scheduled task triggers
                $TaskTriggerList = New-Object -TypeName "System.Collections.ArrayList"
    
                if ($PSBoundParameters["Interval"]) {
                    # Construct the scheduled task trigger for interval selection
                    switch ($PSCmdlet.ParameterSetName) {
                        "Daily" {
                            $TaskTrigger = New-ScheduledTaskTrigger -At $Time -Daily -DaysInterval $Frequency
                        }
                        "Hourly" {
                            $TaskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInter (New-TimeSpan -Hours $Frequency)
                        }
                        "Minutes" {
                            $TaskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInter (New-TimeSpan -Minutes $Frequency)
                        }
                    }
    
                    # Add scheduled task trigger to list
                    $TaskTriggerList.Add($TaskTrigger) | Out-Null
                }
    
                if ($PSBoundParameters["Event"]) {
                    # Construct the scheduled task trigger for each event-based selection
                    foreach ($EventItem in $Trigger) {
                        switch ($EventItem) {
                            "AtWorkstationUnlock" {
                                $StateChangeTrigger = Get-CimClass -Namespace "root\Microsoft\Windows\TaskScheduler" -ClassName "MSFT_TaskSessionStateChangeTrigger"
                                $TaskTrigger = New-CimInstance -CimClass $StateChangeTrigger -Property @{ StateChange = 8 } -ClientOnly
                            }
                            "AtLogon" {
                                $TaskTrigger = New-ScheduledTaskTrigger -AtLogOn
                            }
                            "AtStartup" {
                                $TaskTrigger = New-ScheduledTaskTrigger -AtStartup
                            }
                        }
    
                        # Add scheduled task trigger to list
                        $TaskTriggerList.Add($TaskTrigger) | Out-Null
                    }
                }
    
                # Construct the scheduled task settings
                $TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Hidden -DontStopIfGoingOnBatteries -Compatibility "Win8" -RunOnlyIfNetworkAvailable -MultipleInstances "IgnoreNew" -ErrorAction Stop
    
                # Construct the scheduled task XML data
                $ScheduledTask = New-ScheduledTask -Action $TaskAction -Principal $TaskPrincipal -Settings $TaskSettings -Trigger $TaskTriggerList -ErrorAction Stop
    
                # Register the scheduled task
                $Task = Register-ScheduledTask -InputObject $ScheduledTask -TaskName $Name -TaskPath $Path -ErrorAction Stop
            }
            catch [System.Exception] {
                Write-LogEntry -Value "Failed to create notification scheduled task. Error message: $($_.Exception.Message)" -Severity 3
            }
        }
    }

    function Remove-NotificationScheduledTask {

    }

    function New-NotificationActiveSetupKey {

    }

    function Remove-NotificationActiveSetupKey {

    }

    ## Functions to add / remove ActiveSetup notification

    # Initialize notification framework component download from Azure storage account container
    try {
        $StorageAccountContentFiles = Get-AzureStorageContainerContent -StorageAccountName $StorageAccountName -ContainerName $ContainerName -ErrorAction Stop
        if ($StorageAccountContentFiles -ne $null) {
            foreach ($StorageAccountContentFile in $StorageAccountContentFiles) {
                Invoke-AzureStorageContainerContentDownload -ContainerName $ContainerName -FileName $StorageAccountContentFile.Name -Destination $InstallPath
            }

            # Validate config.json file exists in install path after component download
            $NotificationFrameworkConfigJSONFile = Join-Path -Path $InstallPath -ChildPath "config.json"
            if (Test-Path -Path $NotificationFrameworkConfigJSONFile) {
                Write-LogEntry -Value "Successfully detected config.json file in notification framework install directory: $($NotificationFrameworkConfigJSONFile)" -Severity 1

                try {
                    # Read configuration settings
                    $NotificationFrameworkConfiguration = Get-Content -Path $NotificationFrameworkConfigJSONFile -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop

                    try {
                        # Construct notification application arguments based on configuration settings
                        $NotificationApplicationID = $NotificationFrameworkConfiguration.FrameworkSettings.ApplicationID
                        $NotificationApplicationDisplayName = $NotificationFrameworkConfiguration.FrameworkSettings.ApplicationDisplayName
                        $ApplicationArgs = @{
                            "ID" = $NotificationApplicationID
                            "DisplayName" = $NotificationApplicationDisplayName
                            "ShowInSettings" = $NotificationFrameworkConfiguration.FrameworkSettings.ApplicationShowInSettings
                            "ErrorAction" = "Stop"
                        }
                        if (-not([string]::IsNullOrEmpty($NotificationFrameworkConfiguration.FrameworkSettings.ApplicationIconUri))) {
                            $ApplicationArgs.Add("IconUri", $NotificationFrameworkConfiguration.FrameworkSettings.ApplicationIconUri)
                        }
                        
                        # Create notification application
                        Write-LogEntry -Value "Attempting to create notification application with name: $($NotificationApplicationDisplayName)" -Severity 1
                        New-ToastNotificationApp @ApplicationArgs
                        
                        # Unregister existing scheduled task if it exist
                        $NotificationFrameworkUpdateTaskName = "IntuneNotification - Framework Update"
                        $ScheduledTask = Get-ScheduledTask -TaskName $NotificationFrameworkUpdateTaskName -ErrorAction SilentlyContinue
                        if ($ScheduledTask -ne $null) {
                            Write-LogEntry -Value "Existing scheduled task with name '$($NotificationFrameworkUpdateTaskName)' was found, attempting to unregister task" -Severity "1"
                            Unregister-ScheduledTask -TaskName $NotificationFrameworkUpdateTaskName -Confirm:$false
                        }

                        try {
                            # Construct arguments for scheduled task running the Update-NotificationFramework.ps1 script
                            $NotificationFrameworkUpdateTaskArgs = @{
                                "Interval" = $true
                                "Daily" = $true
                                "Frequency" = $NotificationFrameworkConfiguration.FrameworkUpdateSettings.UpdateFrequency
                                "Time" = [System.DateTime]::Parse($NotificationFrameworkConfiguration.FrameworkUpdateSettings.UpdateTime)
                                "Name" = $NotificationFrameworkUpdateTaskName
                                "Path" = "\$($NotificationFrameworkConfiguration.FrameworkSettings.TaskPathFolderName)"
                                "ProcessName" = "powershell.exe"
                                "Arguments" = "-ExecutionPolicy Bypass -NoProfile -File ""$($InstallPath)\Update-NotificationFramework.ps1"""
                                "Principal" = "System"
                            }

                            # Registed scheduled task for Update-NotificationFramework script
                            Write-LogEntry -Value "Attempting to register scheduled task for notification framework update operations" -Severity 1
                            New-NotificationScheduledTask @NotificationFrameworkUpdateTaskArgs


                            ## Validate modules....

                            # Create modules

                        }
                        catch [System.Exception] {
                            Write-LogEntry -Value "Failed to create scheduled task fr notification framework update operations. Error message: $($_.Exception.Message)" -Severity 3
                        }
                    }
                    catch [System.Exception] {
                        Write-LogEntry -Value "Failed to create notification application with name '$($NotificationApplicationDisplayName)' and ID '$($NotificationApplicationID)'. Error message: $($_.Exception.Message)" -Severity 3
                    }
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "Failed to read notification framework configuration file. Error message: $($_.Exception.Message)" -Severity 3
                }
            }
            else {
                Write-LogEntry -Value "Unable to detect config.json file in notification framework install directory" -Severity 3
            }
        }
        else {
            Write-LogEntry -Value "Unable to locate any notification framework component files in specified Azure storage account container" -Severity 3
        }
    }
    catch [System.Exception] {
        Write-LogEntry -Value "Failed to initialize notification framework component contents from Azure storage container. Error message: $($_.Exception.Message)" -Severity 3
    }
}