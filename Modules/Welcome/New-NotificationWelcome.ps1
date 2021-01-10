<#
.SYNOPSIS
    Create a new welcome notification.

.DESCRIPTION
    Create a new welcome notification.

.EXAMPLE
    .\New-WelcomeNotification.ps1

.NOTES
    FileName:    New-WelcomeNotification.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2020-12-07
    Updated:     2020-12-07

    Version history:
    1.0.0 - (2020-12-07) Script created
#>
Process {
    # Functions
    function New-ToastNotificationApp {
        [CmdletBinding()]
        param(
            [parameter(Mandatory = $true, HelpMessage = "Test")]
            [ValidateNotNullOrEmpty()]
            [string]$ID,
    
            [parameter(Mandatory = $true, HelpMessage = "Test")]
            [ValidateNotNullOrEmpty()]
            [string]$DisplayName,
            
            [parameter(Mandatory = $false, HelpMessage = "Test")]
            [ValidateNotNullOrEmpty()]
            [int]$ShowInSettings = 0,
    
            [parameter(Mandatory = $false, HelpMessage = "Test")]
            [ValidateNotNullOrEmpty()]
            [string]$IconUri = "%SystemRoot%\ImmersiveControlPanel\images\logo.png"
        )
        Begin {
            # Mount the HKEY_CLASSES_ROOT hive drive if not already available
            $HKCRDrive = Get-PSDrive -Name "HKCR" -ErrorAction SilentlyContinue
            if (-not($HKCRDrive)) {
                New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Scope "Script" | Out-Null
            }
        }
        Process {
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
    
            # Dismount the HKEY_CLASSES_ROOT hive drive
            Remove-PSDrive -Name "HKCR" -Force
        }
    }

    # Create a new toast notification app or ensure the MSEndpointMgr.Notification is correctly configured
    $ToastNotificationAppID = "MSEndpointMgr.Notification"
    $ToastNotificationAppDisplayName = "MSEndpointMgr Notification"
    New-ToastNotificationApp -ID $ToastNotificationAppID -DisplayName $AppDisplayName

    # Load required image files
    $HeroImageFile = Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath "HeroImage.png")
    $LogoImageFile = Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath "LogoImage.png")

    # Path to the notification app doing the actual toast
    $NotificationApplicationName = "MSEndpointMgr.Notification"

    # Define toast notification values
    $Heading = "Welcome"
    $HeadingDescription = "Provisioning completed"
    $PrimaryContent = "Welcome to MSEndpointMgr"
    $SecondaryContent = ""

    [xml]$XMLToastContent = @"
        <toast scenario="reminder">
        <visual>
            <binding template="ToastGeneric">
                <image placement="hero" src="$($HeroImageFile)" />
                <image id="1" placement="appLogoOverride" hint-crop="circle" src="$($LogoImageFile)"/>
                <text placement="attribution">$($HeadingDescription)</text>
                <text>$($Heading)</text>
                <group>
                    <subgroup>
                        <text hint-style="body" hint-wrap="true">$($PrimaryContent)</text>
                    </subgroup>
                </group>
                <group>
                    <subgroup>
                        <text hint-style="body" hint-wrap="true">$($SecondaryContent)</text>
                    </subgroup>
                </group>
            </binding>
        </visual>
        <actions>
            <action activationType="system" arguments="dismiss" content="Close"/>
        </actions>
    </toast>
"@

    # Load required runtimes
    $NotificationRuntime = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
    $XmlDocumentRuntime = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]

    # Construct a XmlDocument and load XML content
    $ToastXmlDocument = New-Object -TypeName Windows.Data.Xml.Dom.XmlDocument
    $ToastXmlDocument.LoadXml($XMLToastContent.OuterXml)

    # Invoke toast notification manager to create the toast notification
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($NotificationApplicationName).Show($ToastXmlDocument)
}