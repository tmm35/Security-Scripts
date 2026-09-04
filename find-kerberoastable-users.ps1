<#
.SYNOPSIS
    Identifies Kerberoastable user accounts (SPN-set) and scores risk with a stated
    reason. No TGS tickets are requested - pure LDAP read, no 4769 events. Requires
    only standard domain user read rights.

#>

[CmdletBinding()]
param(
    [int]$PasswordAgeThresholdDays = 365
)

Import-Module ActiveDirectory -ErrorAction Stop

$privilegedGroups = @(
    'Domain Admins', 'Enterprise Admins', 'Schema Admins',
    'Administrators', 'Account Operators', 'Backup Operators',
    'Server Operators', 'Print Operators'
)

function Get-EncryptionTypeLabel {
    param([Nullable[int]]$Value)
    if (-not $Value -or $Value -eq 0) { return '(none set)' }
    $flags = @()
    if ($Value -band 0x1)  { $flags += 'DES-CBC-CRC' }
    if ($Value -band 0x2)  { $flags += 'DES-CBC-MD5' }
    if ($Value -band 0x4)  { $flags += 'RC4-HMAC' }
    if ($Value -band 0x8)  { $flags += 'AES128' }
    if ($Value -band 0x10) { $flags += 'AES256' }
    return ($flags -join ', ')
}

function Get-AccountEncryptionInfo {
    param([Nullable[int]]$AccountValue)

    if ($AccountValue -and $AccountValue -ne 0) {
        $accountAllowsRC4 = [bool]($AccountValue -band 0x4)
        $label = Get-EncryptionTypeLabel -Value $AccountValue

        if ($accountAllowsRC4) {
            return [PSCustomObject]@{ Label = "$label (RC4 permitted by account attribute)"; RC4Possible = $true }
        }
        return [PSCustomObject]@{ Label = "$label (account attribute excludes RC4)"; RC4Possible = $false }
    }

    return [PSCustomObject]@{ Label = 'Unset on account - domain KDC policy not checked by this script, confirm manually'; RC4Possible = $null }
}

function Get-AccountRisk {
    param($PasswordNeverExpires, $PasswordAgeDays, $IsPrivileged, $RC4Possible, $Threshold)

    if ($IsPrivileged) {
        return [PSCustomObject]@{
            Risk   = 'Critical'
            Reason = 'SPN set on an account with privileged access (AdminCount=1 or member of a Tier 0 group) - a cracked password grants privileged domain access directly, regardless of encryption type.'
        }
    }
    if ($RC4Possible -eq $true -and $PasswordNeverExpires) {
        return [PSCustomObject]@{
            Risk   = 'High'
            Reason = 'RC4 is permitted for this account and PasswordNeverExpires is set, so the password may never rotate - an attacker gets unlimited time to crack an offline RC4 hash.'
        }
    }
    if ($RC4Possible -eq $true -and $PasswordAgeDays -ge $Threshold) {
        return [PSCustomObject]@{
            Risk   = 'High'
            Reason = "RC4 is permitted and the password is $PasswordAgeDays days old (threshold: $Threshold), raising the odds it's weak, reused, or already compromised."
        }
    }
    if ($RC4Possible -eq $true) {
        return [PSCustomObject]@{
            Risk   = 'Medium'
            Reason = 'RC4 is permitted for this account. RC4-HMAC hashes crack dramatically faster offline than AES, even with no other risk factors present.'
        }
    }
    if ($RC4Possible -eq $null -and ($PasswordNeverExpires -or $PasswordAgeDays -ge $Threshold)) {
        $ageNote = if ($PasswordNeverExpires) { 'password never expires' } else { "password is $PasswordAgeDays days old" }
        return [PSCustomObject]@{
            Risk   = 'Medium'
            Reason = "Encryption type is unverified (attribute unset - depends on KDC policy this script doesn't check), and $ageNote - confirm domain KDC policy and treat as at-risk until AES-only is verified."
        }
    }
    if ($RC4Possible -eq $null) {
        return [PSCustomObject]@{
            Risk   = 'Low-Unverified'
            Reason = 'Encryption type is unverified (attribute unset). No other risk factors present, but confirm this account gets AES tickets before ruling it out.'
        }
    }
    if ($PasswordAgeDays -ge $Threshold) {
        return [PSCustomObject]@{
            Risk   = 'Medium'
            Reason = "AES enforced on this account's attribute, but password is $PasswordAgeDays days old (threshold: $Threshold) - stale rotation still worth remediating even though offline cracking is harder."
        }
    }
    return [PSCustomObject]@{
        Risk   = 'Low'
        Reason = "AES enforced on this account's attribute and password age is within threshold."
    }
}

Write-Host "[*] Querying AD for SPN-bearing user accounts..." -ForegroundColor Cyan
$accounts = Get-ADUser -Filter {ServicePrincipalName -like '*' -and Enabled -eq $true} `
    -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires, AdminCount, `
                MemberOf, msDS-SupportedEncryptionTypes, Description
Write-Host "[*] Found $($accounts.Count) enabled account(s) with an SPN set." -ForegroundColor Cyan

$privilegedGroupDNs = foreach ($g in $privilegedGroups) {
    (Get-ADGroup -Filter "Name -eq '$g'" -ErrorAction SilentlyContinue).DistinguishedName
}

$report = foreach ($acct in $accounts) {

    $pwAgeDays = if ($acct.PasswordLastSet) {
        [math]::Round(((Get-Date) - $acct.PasswordLastSet).TotalDays)
    } else { $null }

    $isPrivileged = $false
    foreach ($dn in $acct.MemberOf) {
        if ($privilegedGroupDNs -contains $dn) { $isPrivileged = $true; break }
    }
    if ($acct.AdminCount -eq 1) { $isPrivileged = $true }

    $enc = Get-AccountEncryptionInfo -AccountValue $acct.'msDS-SupportedEncryptionTypes'
    $riskInfo = Get-AccountRisk -PasswordNeverExpires $acct.PasswordNeverExpires -PasswordAgeDays $pwAgeDays `
        -IsPrivileged $isPrivileged -RC4Possible $enc.RC4Possible -Threshold $PasswordAgeThresholdDays

    [PSCustomObject]@{
        SamAccountName        = $acct.SamAccountName
        SPNs                  = ($acct.ServicePrincipalName -join '; ')
        Risk                  = $riskInfo.Risk
        Reason                = $riskInfo.Reason
        PasswordAgeDays       = $pwAgeDays
        PasswordNeverExpires  = $acct.PasswordNeverExpires
        AccountEncryptionAttr = $enc.Label
        AdminCountFlag        = ($acct.AdminCount -eq 1)
        PrivilegedGroupMember = $isPrivileged
        Description           = $acct.Description
    }
}

$riskOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low-Unverified' = 3; 'Low' = 4 }
$riskColor = @{ 'Critical' = 'Red'; 'High' = 'Yellow'; 'Medium' = 'DarkYellow'; 'Low-Unverified' = 'Gray'; 'Low' = 'Green' }

$sorted = $report | Sort-Object @{Expression={$riskOrder[$_.Risk]}}, SamAccountName

Write-Host "`n=== KERBEROASTABLE ACCOUNTS: $($report.Count) found ===" -ForegroundColor White
foreach ($level in 'Critical','High','Medium','Low-Unverified','Low') {
    $count = ($report | Where-Object Risk -eq $level).Count
    if ($count -gt 0) { Write-Host ("  {0,-15} {1}" -f "${level}:", $count) -ForegroundColor $riskColor[$level] }
}

foreach ($item in $sorted) {
    $color = $riskColor[$item.Risk]
    Write-Host "`n----------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ("[{0}] {1}" -f $item.Risk.ToUpper(), $item.SamAccountName) -ForegroundColor $color
    Write-Host ("  SPN(s):          {0}" -f $item.SPNs)
    Write-Host ("  Password Age:    {0} days" -f $item.PasswordAgeDays)
    Write-Host ("  Never Expires:   {0}" -f $item.PasswordNeverExpires)
    Write-Host ("  Encryption Attr: {0}" -f $item.AccountEncryptionAttr)
    Write-Host ("  Privileged:      {0}" -f $item.PrivilegedGroupMember)
    if ($item.Description) { Write-Host ("  Description:     {0}" -f $item.Description) }
    Write-Host ("  Reason:          {0}" -f $item.Reason) -ForegroundColor $color
}
Write-Host "----------------------------------------------------------------`n" -ForegroundColor DarkGray

$criticalCount = ($report | Where-Object Risk -eq 'Critical').Count
if ($criticalCount -gt 0) {
    Write-Host "[!] $criticalCount privileged account(s) are Kerberoastable. Fix these first: rotate to a long random password (25+ chars) or migrate to a gMSA." -ForegroundColor Red
}

$unverifiedCount = ($report | Where-Object { $_.AccountEncryptionAttr -like 'Unset*' }).Count
if ($unverifiedCount -gt 0) {
    Write-Host "[*] $unverifiedCount account(s) have no encryption type set on the attribute - this script does not check domain KDC policy, so confirm separately whether your DCs enforce AES-only." -ForegroundColor DarkYellow
}
