<#
.SYNOPSIS


.DESCRIPTION


.PARAMETER Param
    Param description.

.PARAMETER ShowProgress
    Show a progressbar displaying the current operation.

.EXAMPLE


.NOTES
    FileName:    <script name>.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2020-12-13
    Updated:     2020-12-13

    Version history:
    1.0.0 - (2020-12-13) Script created
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [parameter(Mandatory = $true, HelpMessage = "Param description.")]
    [ValidateNotNullOrEmpty()]
    [string]$Param,

    [parameter(Mandatory = $false, HelpMessage = "Show a progressbar displaying the current operation.")]
    [switch]$ShowProgress
)
Begin {}
Process {
    # Functions

    function Remove-NotificationScheduledTask {

    }

    function New-NotificationActiveSetupKey {

    }

    function Remove-NotificationActiveSetupKey {

    }
}