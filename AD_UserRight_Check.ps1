$final = @()
$failedDomains = @()
$workingDomains = @()
$failedDCs = @()

# Query and validate all the domains including child domains and also check the AD connectivity
try {
    $forest = Get-ADForest
    $domains = @()

    Write-Host "Checking domain connectivity..."
    foreach ($domain in $forest.Domains) {
        try {
            $dnsCheck = Resolve-DnsName -Name $domain -ErrorAction Stop
            $dcCheck = Get-ADDomainController -Discover -DomainName $domain -ErrorAction Stop
            $domains += $domain
            $workingDomains += $domain
            Write-Host "Domain OK: $domain"
        } catch {
            Write-Host "Skipping unreachable or orphaned domain: $domain"
            $failedDomains += $domain
        }
    }
} catch {
    Write-Host "Error retrieving domains from AD Forest: $_"
    exit
}

Write-Host "Active Domains for Querying:"
$domains | ForEach-Object { Write-Host $_ }

# for Domain mapping
function Extract-DomainFromDN {
    param ($DN)
    if ($DN -match "DC=(.+?),DC=(.+?)$") {
        return "$($matches[1]).$($matches[2])"
    }
    return "Unknown"
}

# Gather the security policies from all AD DCs
$files = Get-ChildItem C:\Temp\SecuritySettings-*.txt -ErrorAction Stop
$fileContent = foreach ($file in $files) { Get-Content $file.FullName -ErrorAction Stop }

foreach ($po in $fileContent) {
    if ($po -match "=") {
        $poname = ($po -split ' = ')[0]
        if ($poname[0] -ne 's' -or $poname[1] -ne 'e') { continue }
        $loop = (($po -split ' = ')[1]) -split ','
        if (-not $loop) { continue }
    } else { continue }

    foreach ($ele in $loop) {
        $user = $null
        $grp = $null
        $userDomain = "Unknown"
        $groupDomain = "Unknown"

        foreach ($domain in $domains) {
            try {
                if (-not $user) {
                    $user = Get-ADUser -Filter "SamAccountName -like '$ele'" -Server $domain -Properties Enabled,LastLogonDate,MemberOf,DistinguishedName -ErrorAction SilentlyContinue
                    if ($user) { $userDomain = Extract-DomainFromDN $user.DistinguishedName }
                }
                if (-not $grp) {
                    $grp = Get-ADGroup -Filter "SamAccountName -like '$ele'" -Server $domain -Properties MemberOf,DistinguishedName -ErrorAction SilentlyContinue
                    if ($grp) { $groupDomain = Extract-DomainFromDN $grp.DistinguishedName }
                }
            } catch {
                Write-Host "Error retrieving AD object: $ele in domain: $domain - $_"
            }
        }

        # Translate the SID
        if ($ele[0] -eq "*") {
            foreach ($domain in $domains) {
                try {
                    if (-not $user) { 
                        $user = Get-ADUser -Filter "SID -like '$($ele.Substring(1))'" -Server $domain -Properties Enabled,LastLogonDate,MemberOf,DistinguishedName -ErrorAction SilentlyContinue
                        if ($user) { $userDomain = Extract-DomainFromDN $user.DistinguishedName }
                    }
                    if (-not $grp) {
                        $grp = Get-ADGroup -Filter "SID -like '$($ele.Substring(1))'" -Server $domain -Properties MemberOf,DistinguishedName -ErrorAction SilentlyContinue
                        if ($grp) { $groupDomain = Extract-DomainFromDN $grp.DistinguishedName }
                    }
                } catch {
                    Write-Host "Error resolving SID for: $ele in domain: $domain - $_"
                }
            }
        }

        function Extract-GroupName {
            param ($dnList)
            if ($dnList) {
                return ($dnList | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' })
            }
            return "No Groups"
        }

        # Gather all users and groups
        if ($user -or $grp) {
            $final += [PSCustomObject]@{
                Domain = if ($user) { $userDomain } else { $groupDomain }
                Name = if ($user) { $user.Name } else { $grp.Name }
                SamAccountName = if ($user) { $user.SamAccountName } else { $grp.SamAccountName }
                ObjectClass = if ($user) { $user.ObjectClass } else { $grp.ObjectClass }
                MemberOf = if ($user) { Extract-GroupName $user.MemberOf -join ";" } else { Extract-GroupName $grp.MemberOf -join ";" }
                UserRight = [Collections.Generic.HashSet[string]]@($poname)
                LastLogonDate = if ($user.LastLogonDate) { $user.LastLogonDate } else { "Never" }
                AccountStatus = if ($user.Enabled) { If ($user.Enabled -eq 'True') { 'Active' } else { 'Disabled' } } else { "NA" }
                SourceOfRight = [Collections.Generic.HashSet[string]]@("self")
            }
        }

        # Expand all the AD group members
        if ($grp) {
            $members = @()
            foreach ($domain in $domains) {
                try {
                    $members += (Get-ADGroupMember -Identity "$($grp.SamAccountName)" -Server $domain -Recursive) |
                                Where-Object { $_.ObjectClass -match "user" } |
                                Get-ADUser -Server $domain -Properties MemberOf, Enabled, LastLogonDate, DistinguishedName -ErrorAction SilentlyContinue
                } catch {
                    Write-Host "Error retrieving members for group: $($grp.SamAccountName) in domain: $domain - $_"
                }
            }

            foreach ($member in $members) {
                $memberDomain = Extract-DomainFromDN $member.DistinguishedName

                $final += [PSCustomObject]@{
                    Domain = $memberDomain
                    Name = $member.Name
                    SamAccountName = $member.SamAccountName
                    ObjectClass = $member.ObjectClass
                    MemberOf = Extract-GroupName $member.MemberOf -join ";"
                    UserRight = [Collections.Generic.HashSet[string]]@($poname)
                    LastLogonDate = if ($member.LastLogonDate) { $member.LastLogonDate } else { "Never" }
                    AccountStatus = if ($member.Enabled) { If ($member.Enabled -eq 'True') { 'Active' } else { 'Disabled' } } else { "NA" }
                    SourceOfRight = [Collections.Generic.HashSet[string]]@($grp.SamAccountName)
                }
            }
        }
    }
}

# Finalize the format and export to csv
foreach ($f in $final) {
    $f.MemberOf = $f.MemberOf | Out-String
    $f.UserRight = $f.UserRight | Out-String
    $f.SourceOfRight = $f.SourceOfRight | Out-String
}

# Export
$output = "PrivilegedUserAccounts-MultiDomain.csv"
$final | Export-Csv -Path $output -NoTypeInformation -Encoding UTF8

Write-Host "Exported to $output"
