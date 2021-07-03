<p align="center">
  <a href="https://www.powershellgallery.com/packages/DomainHealthChecker/"><img src="https://img.shields.io/powershellgallery/v/DomainHealthChecker"></a>
  <a href="https://www.powershellgallery.com/packages/DomainHealthChecker/"><img src="https://img.shields.io/badge/platform-windows-green"></a>
  <a href="https://www.powershellgallery.com/packages/DomainHealthChecker/"><img src="https://img.shields.io/github/languages/code-size/t13nn3s/domainhealthchecker"></a>
  <a href="https://www.powershellgallery.com/packages/DomainHealthChecker/"><img src="https://img.shields.io/powershellgallery/dt/DomainHealthChecker"></a>
</p>

<p align="center">
  </p>
  
:information_source:**The current release is only supporting PowerShell 7, we will update the script so that it will be compatibel with version 5.1**:information_source:

# DomainHealthChecker
Is your email domain properly protected against abuse, such as email spoofing? This form of abuse can cause (image) damage to an organization. The PowerShell script DomainHealthChecker.ps1 checks the SPF, DKIM and DMARC record of one or more email domains and gives advice if necessary. 

In short: this PowerShell Script can you use for checking SPF, DKIM and DMARC-record.

## Script installation

```
PS C:\> Install-Script -Name DomainHealthChecker -RequiredVersion 1.3.1
```
With this command you can download and install the script from the PowerShellGallery.

## Update script to the latest version

```
PS C:\> Install-Script DomainHealthChecker -Force
```
To delete the current version and the latest version, run `Install-Script`, and add the `-Force` parameter.


## SYNOPSIS
The `DomainHealthChecker` cmdlet performs a DNS query on the SPF-record, DKIM-record and DMARC-record for the specified domain name. This cmdlet takes the output and is adding some advisory if there is room for improvements for the SPF or DMARC-record.

## SYNTAX

```
DomainHealthChecker [-Name] <String> [-File] <string] [-Server <String[]>] [<CommonParameters>]
```
## EXAMPLES

### EXAMPLE 1
```
PS C:\> DomainHealthChecker -Name binsec.nl
```
This example resolves the SPF-record, DKIM-record (selector1) and DMARC-record for the domain binsec.nl.

### EXAMPLE 2
```
PS C:\> DomainHealthChecker -Name binsec.nl -Server 10.0.0.1
```
This example resolves the SPF-record, DKIM-record (selector1) and DMARC-record for the domain binsec.nl against the DNS server at 10.0.0.1.

### EXAMPLE 3
```
PS C:\> DomainHealthChecker -File $env:USERPROFILE\Desktop\domain_list.txt
```

This example takes the list of domains from the file `domain_list.txt` and parse the domains through the SPF, DKIM and DMARC checker. 

### EXAMPLE 4
```
PS C:\> DomainHealthChecker -File $env:USERPROFILE\Desktop\domain_list.txt | Export-Csv destination.csv -NoTypeInformation -Delimiter ";"
```

This example takes the list of domains from the file `domain_list.txt` and parse the domains through the SPF, DKIM and DMARC checker. 



