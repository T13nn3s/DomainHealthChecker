<#
.SYNOPSIS
Detects the operating system platform (macOS, Windows, or Linux).

.DESCRIPTION
This function identifies the operating system platform on which the script is running and outputs whether it is macOS, Windows, or Linux.
Useful for adding crossplatform support for the DomainHealthChecker module.

.EXAMPLE
Get-OsPlatform
#>

function Get-OsPlatform {

    begin {
        Write-Verbose "Starting $($MyInvocation.MyCommand)"
        $osPlatformObject = New-Object System.Collections.Generic.List[System.Object]
    }

    Process {
        # Check if PowerShell 5.1 or PowerShell 7 is being used
        if ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1) {
            # PowerShell 5.1 only supported on Windows
            Write-Verbose "PowerShell 5.1 detected."
            Write-Verbose "Platform is Windows."
            $OsPlatform = "Windows"
        }
        elseif ($PSVersionTable.PSVersion.Major -ge 7) {
            Write-Verbose "PowerShell 7 or later is detected."
            # PowerShell 7 or later
            if ($IsWindows) {
                Write-Verbose "Platform is Windows"
                $OsPlatform = "Windows"
            }
            elseif ($IsMacOS) {
                Write-Verbose "Platform is macOS"
                $OsPlatform = "macOS"
            }
            elseif ($IsLinux) {
                Write-Verbose "Platform is Linux"
                $OsPlatform = "Linux"
            }
            else {
                Write-Verbose "Unknown platform. Fallback to Windows"
                $OsPlatform = "Windows"
            }
        }

    } End {
        $OsPlatformReturnValues = New-Object psobject
        $OsPlatformReturnValues | Add-Member NoteProperty "Platform" $osPlatform
        $osPlatformObject.Add($OsPlatformReturnValues)
        $OsPlatformReturnValues
    }
}