param(
    [string]$TargetAccount,                                  # user whose object ACL you're inspecting
    [string]$SourceAccount = $null,                          # optional: principal you're testing (user + nested groups + well-known SIDs)
    [string]$Server = $null,                                 # optional: specific DC/FQDN
    [switch]$IncludeDeny,                                    # optional: also include Deny ACEs in summary
    [switch]$IncludeExtendedRight,                           # optional: include ExtendedRight in output
    [switch]$Help                                            # optional: show usage
)

function Show-Usage {
@"
Usage:
  .\CheckWritePermissions.ps1 -TargetAccount <sam|dn|sid|guid> [-SourceAccount <sam|dn|sid|guid>] [-Server <dc-fqdn>] [-IncludeDeny] [-IncludeExtendedRight] [-Help]

Examples:
  .\CheckWritePermissions.ps1 -TargetAccount JohnDoe
  .\CheckWritePermissions.ps1 -TargetAccount JohnDoe -SourceAccount TonySoprano
  .\CheckWritePermissions.ps1 -TargetAccount JohnDoe -SourceAccount TonySoprano -Server dc01.domain.local
  .\CheckWritePermissions.ps1 -TargetAccount JohnDoe -IncludeExtendedRight
"@
}

function Test-HasAllFlags {
    param(
        [System.DirectoryServices.ActiveDirectoryRights]$Rights,
        [System.DirectoryServices.ActiveDirectoryRights]$Mask
    )
    return (($Rights -band $Mask) -eq $Mask)
}

function Get-ChangeRightNames {
    param(
        [System.DirectoryServices.ActiveDirectoryRights]$Rights,
        [bool]$IncludeExtendedRight = $false
    )

    $names = @()

    # Composite flags: require full-mask match (prevents false positives)
    if (Test-HasAllFlags -Rights $Rights -Mask ([System.DirectoryServices.ActiveDirectoryRights]::GenericAll)) {
        $names += 'GenericAll'
    }
    if (Test-HasAllFlags -Rights $Rights -Mask ([System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)) {
        $names += 'GenericWrite'
    }

    # Atomic flags
    if (($Rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -ne 0) {
        $names += 'WriteProperty'
    }
    if (($Rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -ne 0) {
        $names += 'WriteDacl'
    }
    if (($Rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) -ne 0) {
        $names += 'WriteOwner'
    }
    if (($Rights -band [System.DirectoryServices.ActiveDirectoryRights]::Self) -ne 0) {
        $names += 'Self (Validated Write)'
    }
    if (($Rights -band [System.DirectoryServices.ActiveDirectoryRights]::Delete) -ne 0) {
        $names += 'Delete'
    }
    if (($Rights -band [System.DirectoryServices.ActiveDirectoryRights]::DeleteTree) -ne 0) {
        $names += 'DeleteTree'
    }

    if ($IncludeExtendedRight -and (($Rights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne 0)) {
        $names += 'ExtendedRight'
    }

    return ($names | Sort-Object -Unique)
}

function Format-ChangeRightsHighlighted {
    param([string[]]$Rights)

    $toHighlight = @('GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner')

    $supportsAnsi = $false
    if ($Host.Name -notmatch 'ISE') {
        try { $supportsAnsi = [bool]$Host.UI.SupportsVirtualTerminal } catch { $supportsAnsi = $true }
    }

    $sorted = $Rights | Where-Object { $_ } | Sort-Object -Unique
    $esc = [char]27

    $formatted = foreach ($r in $sorted) {
        if ($toHighlight -contains $r) {
            if ($supportsAnsi) { "$esc[30;103m$r$esc[0m" } else { "[$r]" }
        } else {
            $r
        }
    }

    return ($formatted -join ', ')
}

function Test-IsExcludedPrincipal {
    param([string]$Identity)

    if ([string]::IsNullOrWhiteSpace($Identity)) { return $true }

    # Must look like DOMAIN\Name
    if ($Identity -notmatch '^[^\\]+\\[^\\]+$') { return $true }

    $parts = $Identity.Split('\', 2)
    $domainPart = $parts[0]
    $namePart   = $parts[1]

    # Exclude non-AD/system/builtin authorities
    if ($domainPart -match '^(?i:NT AUTHORITY|BUILTIN|NT SERVICE)$') { return $true }

    # Exclude host/computer principals
    if ($namePart -like '*$') { return $true }

    # Exclude common non-user/group aliases
    $excludedNames = @(
        'Everyone',
        'LOCAL SERVICE',
        'NETWORK SERVICE',
        'SYSTEM',
        'SELF',
        'CREATOR OWNER',
        'CREATOR GROUP',
        'ANONYMOUS LOGON',
        'ENTERPRISE DOMAIN CONTROLLERS'
    )
    if ($excludedNames -contains $namePart) { return $true }

    # Exclude raw SID-form identities
    if ($Identity -match '^S-\d-') { return $true }

    return $false
}

# If no args or -Help, print usage and exit cleanly
if ($Help -or $PSBoundParameters.Count -eq 0) {
    Show-Usage
    return
}

# Manual required-check
if (-not $PSBoundParameters.ContainsKey('TargetAccount') -or [string]::IsNullOrWhiteSpace($TargetAccount)) {
    Show-Usage
    return
}

Import-Module ActiveDirectory
$ErrorActionPreference = 'Stop'

try {
    # Resolve writable DC if -Server not supplied
    if (-not $Server) {
        $dcObj  = Get-ADDomainController -Discover -Writable -ErrorAction Stop
        $Server = [string](($dcObj.HostName, $dcObj.Name, $dcObj.IPv4Address | Where-Object { $_ })[0])
    }

    if ([string]::IsNullOrWhiteSpace($Server)) {
        throw "Could not resolve a valid domain controller for -Server."
    }

    # Resolve target user
    $target = Get-ADUser -Identity $TargetAccount -Server $Server -Properties SID, DistinguishedName

    # Build SID set for source account (if provided)
    $sids = $null
    if ($SourceAccount) {
        $check   = Get-ADUser -Identity $SourceAccount -Server $Server -Properties SID, DistinguishedName
        $checkTG = Get-ADUser -Identity $check.DistinguishedName -Server $Server -Properties SID, tokenGroups

        $sids = @($checkTG.SID.Value) + @($checkTG.tokenGroups | ForEach-Object { $_.Value })

        # Common delegation principals
        $sids += 'S-1-1-0'   # Everyone
        $sids += 'S-1-5-11'  # Authenticated Users

        # SELF only if same principal
        if ($checkTG.SID.Value -eq $target.SID.Value) {
            $sids += 'S-1-5-10'
        }

        $sids = $sids | Sort-Object -Unique
    }

    # Read ACL via ADSI
    $de  = [ADSI]"LDAP://$Server/$($target.DistinguishedName)"
    $acl = $de.ObjectSecurity

    $results = foreach ($ace in $acl.Access) {
        try {
            $aceSid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        }
        catch {
            continue
        }

        $grantedThrough = [string]$ace.IdentityReference.Value

        # Keep only AD user/group style principals, exclude host/system-related
        if (Test-IsExcludedPrincipal -Identity $grantedThrough) {
            continue
        }

        # Exclude InheritOnly ACEs (not effective on the current object itself)
        if (($ace.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) {
            continue
        }

        # SID filter (if SourceAccount provided)
        if ($sids -and -not ($sids -contains $aceSid)) {
            continue
        }

        # By default only Allow ACEs
        if (-not $IncludeDeny -and $ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
            continue
        }

        $rights = [System.DirectoryServices.ActiveDirectoryRights]$ace.ActiveDirectoryRights
        $changeRights = Get-ChangeRightNames -Rights $rights -IncludeExtendedRight:$IncludeExtendedRight.IsPresent

        if (@($changeRights).Count -eq 0) {
            continue
        }

        [PSCustomObject]@{
            GrantedThrough = $grantedThrough
            GrantedSid     = $aceSid      # internal grouping only
            AceType        = [string]$ace.AccessControlType
            Inherited      = $ace.IsInherited
            ChangeRights   = $changeRights
        }
    }

    if (@($results).Count -gt 0) {
        $summary = $results |
            Group-Object GrantedSid |
            ForEach-Object {
                $g = $_.Group

                $inheritedValues  = $g.Inherited | Sort-Object -Unique
                $inheritedDisplay = if ($inheritedValues.Count -eq 1) { [string]$inheritedValues[0] } else { 'Mixed' }

                [PSCustomObject]@{
                    GrantedThrough = ($g.GrantedThrough | Sort-Object -Unique) -join ', '
                    Inherited      = $inheritedDisplay
                    ChangeRights   = Format-ChangeRightsHighlighted -Rights ($g.ChangeRights | ForEach-Object { $_ })
                }
            }

        $summary |
            Sort-Object GrantedThrough |
            Format-Table GrantedThrough, Inherited, ChangeRights -AutoSize

        if ($IncludeDeny -and (@($results | Where-Object { $_.AceType -eq 'Deny' }).Count -gt 0)) {
            Write-Host "Note: Deny ACE(s) are included because -IncludeDeny was used." -ForegroundColor DarkYellow
        }
    }
    elseif ($SourceAccount) {
        Write-Host "$SourceAccount has no matching change-capable ACEs over $TargetAccount" -ForegroundColor Yellow
    }
    else {
        Write-Host "No change-capable ACEs found over $TargetAccount" -ForegroundColor Yellow
    }
}
catch {
    Write-Error "Failed: $($_.Exception.Message)"
}
