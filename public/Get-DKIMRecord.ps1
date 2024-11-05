<#>
HelpInfoURI 'https://github.com/T13nn3s/Show-SpfDkimDmarc/blob/main/public/CmdletHelp/Get-DKIMRecord.md'
#>

function Get-DKIMRecord {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Specifies the domain for resolving the DKIM-record."
        )][string[]]$Name,

        [Parameter(Mandatory = $False,
            HelpMessage = "Specify a custom DKIM selector.")]
        [string]$DkimSelector,

        [Parameter(Mandatory = $false,
            HelpMessage = "DNS Server to use.")]
        [string]$Server
    )

    begin {

        Write-Verbose "Starting $($MyInvocation.MyCommand)"
        $PSBoundParameters | Out-String | Write-Verbose
        
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
                
        # Custom list of DKIM-selectors
        # See: https://help.sendmarc.com/support/solutions/articles/44001891845-email-provider-commonly-used-dkim-selectors
        # See: https://www.reddit.com/r/DMARC/comments/1bffol7/list_of_most_common_dkim_selectors/
        $DkimSelectors = @(
            'selector1' # Microsoft
            'selector2' # Microsoft
            'google' # Google Workspace
            'everlytickey1' # Everlytic
            'everlytickey2' # Everlytic
            'eversrv' # Everlytic OLD selector
            'k1' # Mailchimp / Mandrill
            'k2' # Mailchimp / Mandrill
            'mxvault' # Global Micro
            'dkim' # Hetzner
            's1' # Sendgrid / NationBulder
            's2' # Sendgrid / NationBuilder
            'ctct1' # Constant Contact
            'ctct2' # Constant Contact
            'sm' # Blackbaud, eTapestry
            'sig1' # iCloud
            'litesrv' # MailerLite
            'zendesk1' # Zendesk
            'zendesk2' # Zendesk
        )

        $DKimObject = New-Object System.Collections.Generic.List[System.Object]
    }

    Process {
        foreach ($domain in $Name) {
    
        if ($DkimSelector) {
            $DKIM = Resolve-DnsName -Type TXT -Name "$($DkimSelector)._domainkey.$($domain)" @SplatParameters
            if ($DKIM.Type -eq "CNAME") {
                while ($DKIM.Type -eq "CNAME") {
                    $DKIMCname = $DKIM.NameHost
                    $DKIM = Resolve-DnsName -Type TXT -name "$DKIMCname" @SplatParameters 
                }
                $DKIM = $DKIM | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue
                if ($null -eq $DKIM) {
                    $DkimAdvisory = "No DKIM-record found for selector $($DkimSelector)._domainkey."
                }
                elseif ($DKIM -match "v=DKIM1" -or $DKIM -match "k=") {
                    $DkimAdvisory = "DKIM-record found."
                }
            } 
            else {
                $DKIM = $DKIM | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue
                if ($null -eq $DKIM) {
                    $DkimAdvisory = "No DKIM-record found for selector $($DkimSelector)._domainkey."
                }
                elseif ($DKIM -match "v=DKIM1" -or $DKIM -match "k=") {
                    $DkimAdvisory = "DKIM-record found."
                }
            }
        }
        else {
            foreach ($DkimSelector in $DkimSelectors) {
                $DKIM = Resolve-DnsName -Type TXT -Name  "$($DkimSelector)._domainkey.$($domain)" @SplatParameters
                if ($DKIM.Type -eq "CNAME") {
                    while ($DKIM.Type -eq "CNAME") {
                        $DKIMCname = $DKIM.NameHost
                        $DKIM = Resolve-DnsName -Type TXT -name "$DKIMCname" @SplatParameters 
                    }
                    $DKIM = $DKIM | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue
                    if ($null -eq $DKIM) {
                        $DkimAdvisory = "No DKIM-record found for selector $($DkimSelector)._domainkey."
                    }
                    elseif ($DKIM -match "v=DKIM1" -or $DKIM -match "k=") {
                        $DkimAdvisory = "DKIM-record found."
                        break
                    }
                }
                else {
                    $DKIM = $DKIM | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue
                    if ($null -eq $DKIM) {
                        $DkimAdvisory = "We couldn't find a DKIM record associated with your domain."
                    }
                    elseif ($DKIM -match "v=DKIM1" -or $DKIM -match "k=") {
                        $DkimAdvisory = "DKIM-record found."
                        break
                    }
                }
                 
                }
            }
            $DkimReturnValues = New-Object psobject
            $DkimReturnValues | Add-Member NoteProperty "Name" $domain
            $DkimReturnValues | Add-Member NoteProperty "DkimRecord" $DKIM
            $DkimReturnValues | Add-Member NoteProperty "DkimSelector" $DkimSelector
            $DkimReturnValues | Add-Member NoteProperty "DKIMAdvisory" $DkimAdvisory
            $DkimObject.Add($DkimReturnValues)
            $DkimReturnValues
        }
    } end {}
}
Set-Alias gdkim -Value Get-DKIMRecord     
