<#>
HelpInfoURI 'https://github.com/T13nn3s/Show-SpfDkimDmarc/blob/main/public/CmdletHelp/Invoke-SpfDkimDmarc.md'
#>

# Load public functions
Get-ChildItem -Path $PSScriptRoot\public\*.ps1 | 
ForEach-Object {
    . $_.FullName
}

# Load private functions
Get-ChildItem -Path $PSScriptRoot\private\*.ps1 |
ForEach-Object {
    . $_.FullName
}

function Invoke-SpfDkimDmarc {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory, ParameterSetName = 'domain',
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Specifies the domain for resolving the SPF, DKIM and DMARC-record.",
            Position = 1)]
        [string[]]$Name,

        [Parameter(
            Mandatory, ParameterSetName = 'file',
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Show SPF, DKIM and DMARC-records from multiple domains from a file.",
            Position = 2)]
        [Alias('Path')]
        [System.IO.FileInfo]$File,

        [Parameter(Mandatory = $False,
            HelpMessage = "Specify a custom DKIM selector.",
            Position = 3)]
        [string]$DkimSelector,

        [Parameter(Mandatory = $false,
            HelpMessage = "DNS Server to use.",
            Position = 4)]
        [string]$Server,

        [Parameter(Mandatory = $False,
            HelpMessage = "Include this switch to check for DNSSEC existance",
            Position = 5)]
        [switch]$IncludeDNSSEC
    )

    begin {
        Write-Verbose "Starting $($MyInvocation.MyCommand)"
        $PSBoundParameters | Out-String | Write-Verbose

        $InvokeObject = New-Object System.Collections.Generic.List[System.Object]        
    } process {

        $Splat = @{}
        $DKIMSplat = @{}

        switch -Regex ($True) { 
            { $Server -and !$DkimSelector -and !$IncludeDNSSEC } {
                $Splat += @{ 
                    'Server' = $Server
                } 
            } 
            { $DkimSelector -and !$Server -and !$IncludeDNSSEC } {
                $DKIMSplat += @{
                    'DkimSelector' = $DkimSelector
                } 
            } 
            { $DkimSelector -and $Server -and !$IncludeDNSSEC } { 
                $DKIMSplat += @{
                    'Server'       = $Server
                    'DkimSelector' = $DkimSelector
                } 
            } 
            { $IncludeDNSSEC -and $Server -and !$DkimSelector } {
                $Splat += @{ 
                    'Server'        = $Server
                    'IncludeDNSSEC' = $True
                } 
            } 
            { $IncludeDNSSEC -and $Server -and $DkimSelector } {
                $DKIMSplat += @{
                    'Server'        = $Server
                    'DkimSelector'  = $DkimSelector
                    'IncludeDNSSEC' = $True 
                } 
            } 
        }

        # If 'File' parameter is used
        if ($PSBoundParameters.ContainsKey('File')) {
            foreach ($Name in (Get-Content -Path $File)) {
                $SPF = Get-SPFRecord -Name $Name @Splat
                $DKIM = Get-DKIMRecord -Name $Name @Splat @DKIMSplat
                $DMARC = Get-DMARCRecord -Name $Name @Splat
                $MTASTS = Invoke-MtaSTS -Name $Name @Splat

                if ($PSBoundParameters.ContainsKey('IncludeDNSSEC')) {
                    $DNSSEC = Get-DNSSec -Name $Name @Splat
                }

                $InvokeReturnValues = New-Object psobject
                $InvokeReturnValues | Add-Member NoteProperty "Name" $SPF.Name
                $InvokeReturnValues | Add-Member NoteProperty "SpfRecord" $SPF.SPFRecord
                $InvokeReturnValues | Add-Member NoteProperty "SpfAdvisory" $SPF.SpfAdvisory
                $InvokeReturnValues | Add-Member NoteProperty "SPFRecordLength" $SPF.SPFRecordLength
                $InvokeReturnValues | Add-Member NoteProperty "DmarcRecord" $DMARC.DmarcRecord
                $InvokeReturnValues | Add-Member NoteProperty "DmarcAdvisory" $DMARC.DmarcAdvisory
                $InvokeReturnValues | Add-Member NoteProperty "DkimRecord" "$($DKIM.DkimRecord)"
                $InvokeReturnValues | Add-Member NoteProperty "DkimSelector" $DKIM.DkimSelector
                $InvokeReturnValues | Add-Member NoteProperty "MtaRecord" $MTASTS.mtaRecord
                $InvokeReturnValues | Add-Member NoteProperty "MtaAdvisory" $MTASTS.mtaAdvisory

                if ($PSBoundParameters.ContainsKey('IncludeDNSSEC')) {
                    $InvokeReturnValues | Add-Member NoteProperty "DnsSec" $DNSSEC.DNSSEC
                    $InvokeReturnValues | Add-Member NoteProperty "DnsSecAdvisory" $DNSSEC.DnsSecAdvisory
                }

                $InvokeObject.Add($InvokeReturnValues)
                $InvokeReturnValues
            }
        }

        # If 'Name' parameter is used
        if ($PSBoundParameters.ContainsKey('Name')) {
            foreach ($domain in $Name) {
                $SPF = Get-SPFRecord -Name $domain @Splat
                $DKIM = Get-DKIMRecord -Name $domain @Splat @DKIMSplat
                $DMARC = Get-DMARCRecord -Name $domain @Splat
                $MTASTS = Invoke-MtaSTS -Name $domain @Splat
            
                if ($PSBoundParameters.ContainsKey('IncludeDNSSEC')) {
                    $DNSSEC = Get-DNSSec -Name $domain @Splat
                }

                $InvokeReturnValues = New-Object psobject
                $InvokeReturnValues | Add-Member NoteProperty "Name" $SPF.Name
                $InvokeReturnValues | Add-Member NoteProperty "SpfRecord" $SPF.SPFRecord
                $InvokeReturnValues | Add-Member NoteProperty "SpfAdvisory" $SPF.SpfAdvisory
                $InvokeReturnValues | Add-Member NoteProperty "SPFRecordLength" $SPF.SPFRecordLength
                $InvokeReturnValues | Add-Member NoteProperty "DmarcRecord" $DMARC.DmarcRecord
                $InvokeReturnValues | Add-Member NoteProperty "DmarcAdvisory" $DMARC.DmarcAdvisory
                $InvokeReturnValues | Add-Member NoteProperty "DkimRecord" "$($DKIM.DkimRecord)"
                $InvokeReturnValues | Add-Member NoteProperty "DkimSelector" $DKIM.DkimSelector
                $InvokeReturnValues | Add-Member NoteProperty "DkimAdvisory" $DKIM.DkimAdvisory
                $InvokeReturnValues | Add-Member NoteProperty "MtaRecord" $MTASTS.mtaRecord
                $InvokeReturnValues | Add-Member NoteProperty "MtaAdvisory" $MTASTS.mtaAdvisory

                if ($PSBoundParameters.ContainsKey('IncludeDNSSEC')) {
                    $InvokeReturnValues | Add-Member NoteProperty "DnsSec" $DNSSEC.DNSSEC
                    $InvokeReturnValues | Add-Member NoteProperty "DnsSecAdvisory" $DNSSEC.DnsSecAdvisory
                } 
                $InvokeObject.Add($InvokeReturnValues)
                $InvokeReturnValues
            }
        }
    }
    end {
  
    }
}

Set-Alias Show-SpfDkimDmarc -Value Invoke-SpfDkimDmarc
Set-Alias isdd -Value Invoke-SpfDkimDmarc