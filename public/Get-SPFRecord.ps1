<#>
.HelpInfoURI 'https://github.com/T13nn3s/Show-SpfDkimDmarc/blob/main/public/CmdletHelp/Get-SPFRecord.md'
#>

# Load private functions
Get-ChildItem -Path .\private\*.ps1 |
ForEach-Object {
    . $_.FullName
}

function Get-SPFRecord {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Enter one or more domain names to resolve their SPF records."
        )][string[]]$Name,

        [Parameter(Mandatory = $false,
            HelpMessage = "DNS Server to use.")]
        [string]$Server
    )

    begin {

        Write-Verbose "Starting $($MyInvocation.MyCommand)"
        $PSBoundParameters | Out-String | Write-Verbose

        $OsPlatform = (Get-OsPlatform).Platform

        if ($PSBoundParameters.ContainsKey('Server')) {
            $SplatParameters = @{
                'Server'      = $Server
                'ErrorAction' = 'SilentlyContinue'
            }
        }
        Else {
            $SplatParameters = @{
                'ErrorAction' = 'SilentlyContinue'
            }
        }

        $SpfObject = New-Object System.Collections.Generic.List[System.Object]
    }

    Process {

        foreach ($domain in $Name) {

            if ($OsPlatform -eq "Windows") {
                $SPF = Resolve-DnsName -Name $domain -Type TXT @SplatParameters | where-object { $_.strings -match "v=spf1" } | Select-Object -ExpandProperty strings -ErrorAction SilentlyContinue
            }
            Elseif ($OsPlatform -eq "macOS" -or $OsPlatform -eq "Linux") {
                $SPF = $(dig +short $domain TXT | grep "v=spf1" | Out-String)
            }
            Elseif ($OsPlatform -eq "macOS" -or $OsPlatform -eq "Linux" -and $Server) {
                $SPF = $(dig +short $domain TXT @$SplatParameters.Server | grep "v=spf1" | Out-String)
            }

            if ($SPF -match "redirect") {
                $redirect = $SPF.Split(" ")
                $RedirectName = $redirect -match "redirect" -replace "redirect="

                if ($OsPlatform -eq "Windows") {
                    $SPF = Resolve-DnsName -Name "$RedirectName" -Type TXT @SplatParameters | where-object { $_.strings -match "v=spf1" } | Select-Object -ExpandProperty strings -ErrorAction SilentlyContinue
                }
                Elseif ($OsPlatform -eq "macOS" -or $POslatform -eq "Linux") {
                    $SPF = $(dig +short $RedirectName TXT @$Server | grep "v=spf1" | Out-String)
                }
                Elseif ($OsPlatform -eq "macOS" -or $OsPlatform -eq "Linux" -and $Server) {
                    $SPF = $(dig +short $RedirectName TXT @$SplatParameters.Server | grep "v=spf1" | Out-String)
                }
            }

            # Check for multiple SPF records
            $RecipientServer = "v=spf1"
            $SPFCount = ([regex]::Matches($SPF, $RecipientServer)).Count
            
            if ($null -eq $SPF) {
                $SpfAdvisory = "Domain does not have an SPF record. To prevent abuse of this domain, please add an SPF record to it."
            }
            elseif ($SPFCount -gt 1) {
                $SpfAdvisory = "Domain has more than one SPF record. Only one SPF record per domain is allowed. This is explicitly defined in RFC4408."     
                $SpfTotalLenght = 0
                foreach ($char in $SPF) {
                    $SPFTotalLenght += $char.Length
                    $SpfTotalLenght
                }
            }
            Else {
                $SPF = $SPF -join ""
                $SpfTotalLenght = $SPF.Lenght

                foreach ($mechanism in $SPF) {
                    switch ($SPF) {
                        { $mechanism.Length -gt 255 } {
                            # See: https://datatracker.ietf.org/doc/html/rfc4408#section-3.1.3 
                            $SpfAdvisory = "Your SPF record has more than 255 characters in one string. This MUST not be done as explicitly defined in RFC4408. " 
                            $SpfTotalLenght += $mechanism.Length

                        }
                        { $mechanism.Length -ge 450 } {
                            # See: https://datatracker.ietf.org/doc/html/rfc7208#section-3.4
                            $SpfAdvisory = "Your SPF-record has more than 450 characters. This is SHOULD be avoided according to RFC7208. "
                        }
                    }
            
                    switch -Regex ($SPF) {
                        '~all' {
                            $SpfAdvisory += "An SPF-record is configured but the policy is not sufficiently strict."
                        }
                        '-all' {
                            $SpfAdvisory += "An SPF-record is configured and the policy is sufficiently strict."
                        }
                        "\?all" {
                            $SpfAdvisory += "Your domain has a valid SPF record but your policy is not effective enough."
                        }
                        '\+all' {
                            $SpfAdvisory += "Your domain has a valid SPF record but your policy is not effective enough."
                        }
                        Default {
                            $SpfAdvisory += "No qualifier found. Your domain has a SPF record but your policy is not effective enough."
                        }
                    }
                }
            }

            foreach ($domain in $name) {

                $SpfReturnValues = New-Object psobject
                $SpfReturnValues | Add-Member NoteProperty "Name" $domain
                $SpfReturnValues | Add-Member NoteProperty "SPFRecord" "$($SPF)"
                $SpfReturnValues | Add-Member NoteProperty "SPFRecordLength" "$($SpfTotalLenght)"
                $SpfReturnValues | Add-Member NoteProperty "SPFAdvisory" $SpfAdvisory
                $SpfObject.Add($SpfReturnValues)
                $SpfReturnValues
            }
        } 
    } end {}
} 

Set-Alias gspf -Value Get-SPFRecord