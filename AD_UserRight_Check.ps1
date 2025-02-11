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

# Check the Temp folder is exist on the running host
$TempFolder = "C:\Temp"
if (!(Test-Path $TempFolder)) {
    Write-Host "Creating missing Temp folder on local machine at $TempFolder..."
    New-Item -Path $TempFolder -ItemType Directory -Force | Out-Null
}

# Export the security settings from all AD DCs
$DCs = Get-ADDomainController -Filter * | Where-Object {
    try {
        Resolve-DnsName -Name $_.HostName -ErrorAction Stop
        $true
    } catch {
        Write-Host "Skipping orphaned or unreachable domain controller: $($_.HostName)"
        $failedDCs += $_.HostName
        $false
    }
}

$fileContent = @()
if ($DCs.Count -eq 0) {
    Write-Host "No reachable domain controllers found. Skipping security policy collection."
} else {
    foreach ($dc in $DCs) {
        try {
            # check the Temp folder is exist on each DCs
            Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                if (!(Test-Path "C:\Temp")) {
                    Write-Host "Creating missing Temp folder on $env:COMPUTERNAME..."
                    New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null
                }
            } -ErrorAction Stop

            # export security settings from each DC
            $fileContent += Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                secedit /export /mergedpolicy /cfg "C:\Temp\SecuritySettings-$env:COMPUTERNAME.txt" | Out-Null
                $data = Get-Content "C:\Temp\SecuritySettings-$env:COMPUTERNAME.txt"
                rm "C:\Temp\SecuritySettings-$env:COMPUTERNAME.txt"
                return $data
            } -ErrorAction Stop
        } catch {
            Write-Host "Failed to export security policies from: $($dc.HostName)"
            $failedDCs += $dc.HostName
        }
    }
}

# Gather the security policies from all AD DCs
# $files = Get-ChildItem C:\Temp\SecuritySettings-*.txt -ErrorAction Stop
# $fileContent = foreach ($file in $files) { Get-Content $file.FullName -ErrorAction Stop }

foreach ($po in $fileContent) {
    
    if ($po -match "=") {
        $poname = ($po -split ' = ')[0]
        if ($poname[0] -ne 's' -or $poname[1] -ne 'e') { continue }
        $loop = (($po -split ' = ')[1]) -split ','
        if (-not $loop) { continue }
    } else { continue }

    foreach ($ele in $loop) {

        $users = [PSCustomObject]@{
            user     = @()
            domains    = @()
        }
        $groups = [PSCustomObject]@{
            group     = @()
            domains    = @()
        }
        
        # $user = $null
        # $grp = $null
        # $userDomain = @()
        # $groupDomain = @()
        foreach ($domain in $domains) {
            try {
                $tmp = Get-ADUser -Filter "SamAccountName -like '$ele'" -Server $domain -Properties Enabled,LastLogonDate,MemberOf,DistinguishedName -ErrorAction SilentlyContinue
                if ($tmp) {
                    $users.user += $tmp
                    $users.domains+=$domain
                }
                $tmp = Get-ADGroup -Filter "SamAccountName -like '$ele'" -Server $domain -Properties MemberOf,DistinguishedName -ErrorAction SilentlyContinue
                if ($tmp){
                    $groups.group += $tmp
                    $groups.domains+=$domain
                }
            } catch {
                Write-Host "Error retrieving AD object: $ele in domain: $domain - $_"
            }
        }

        # Translate the SID or SamAccountName
        if ($ele[0] -eq "*") {
            foreach ($domain in $domains) {
                try {
                    $tmp = Get-ADUser -Filter "SID -like '$($ele.Substring(1))'" -Server $domain -Properties Enabled,LastLogonDate,MemberOf,DistinguishedName -ErrorAction SilentlyContinue
                    if ($tmp) {
                        $users.user += $tmp
                        $users.domains+=$domain
                    }
                    $tmp = Get-ADGroup -Filter "SID -like '$($ele.Substring(1))'" -Server $domain -Properties MemberOf,DistinguishedName -ErrorAction SilentlyContinue
                    if ($tmp){
                        $groups.group += $tmp
                        $groups.domains+=$domain
                    }

                    # if (-not $user) { 
                    #     $user = Get-ADUser -Filter "SID -like '$($ele.Substring(1))'" -Server $domain -Properties Enabled,LastLogonDate,MemberOf,DistinguishedName -ErrorAction SilentlyContinue
                    #     if ($user) { $userDomain = Extract-DomainFromDN $user.DistinguishedName }
                    # }
                    # if (-not $grp) {
                    #     $grp = Get-ADGroup -Filter "SID -like '$($ele.Substring(1))'" -Server $domain -Properties MemberOf,DistinguishedName -ErrorAction SilentlyContinue
                    #     if ($grp) { $groupDomain = Extract-DomainFromDN $grp.DistinguishedName }
                    # }
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

        function Check-Existence{
            param ($checklist,$domainName)
            if ($checklist){
                # Write-Host $domainName
                $existingEntry = $final|Where-Object {($_.SamAccountName -eq $checklist.SamAccountName) -and ($_.Domain -eq $domainName)}
                # Write-Host ($existingEntry[0].Domain)
                return $existingEntry
            }
            return ""
        }

        # Gather all users and groups
        if ($users.user.count){
            for ($i = 0; $i -lt $users.user.count;$i = $i+1){
                $existingEntry = Check-Existence $users.user[$i] $users.domain[$i]
                if ($existingEntry){
                    $existingEntry.UserRight.add($poname) |Out-Null
                    $existingEntry.SourceOfRight.add("self") | Out-Null
                }           
                else{
                    
                    $final += [PSCustomObject]@{
                        Domain = $users.domain[$i]
                        Name = $users.user[$i].Name 
                        SamAccountName = $users.user[$i].SamAccountName
                        ObjectClass = $users.user[$i].ObjectClass
                        MemberOf =  Extract-GroupName $users.user[$i].MemberOf -join ";"
                        UserRight = [Collections.Generic.HashSet[string]]@($poname)
                        LastLogonDate = if ($users.user[$i].LastLogonDate) { $users.user[$i].LastLogonDate } else { "Never" }
                        AccountStatus = if ($users.user[$i].Enabled) { If ($users.user[$i].Enabled -eq 'True') { 'Active' } else { 'Disabled' } } else { "NA" }
                        SourceOfRight = [Collections.Generic.HashSet[string]]@("self")
                    }
    
                }
            }
        }

        if ($groups.group.count){
            for ($i = 0; $i -lt $groups.group.count;$i = $i+1){
                $existingEntry = Check-Existence $groups.group[$i] $groups.domains[$i]
                if ($existingEntry){
                    $existingEntry.UserRight.add($poname) |Out-Null
                    $existingEntry.SourceOfRight.add("self") | Out-Null
                }           
                else{
                    
                    $final += [PSCustomObject]@{
                        Domain = $groups.domains[$i]
                        Name = $groups.group[$i].Name 
                        SamAccountName = $groups.group[$i].SamAccountName
                        ObjectClass = $groups.group[$i].ObjectClass
                        MemberOf =  Extract-GroupName $groups.group[$i].MemberOf -join ";"
                        UserRight = [Collections.Generic.HashSet[string]]@($poname)
                        LastLogonDate = "Never" 
                        AccountStatus =  "NA" 
                        SourceOfRight = [Collections.Generic.HashSet[string]]@("self")
                    }
    
                }
            }
        }




        # if ($user -or $grp) {
        #     # check if it is in the list already
        #     $existingEntry = if ($user) {Check-Existence $user $userDomain} else {Check-Existence $grp $groupDomain}

        #     if ($existingEntry){
        #         #this group has been processed before
        #         $existingEntry.UserRight.add($poname) |Out-Null
        #         $existingEntry.SourceOfRight.add("self") | Out-Null
        #     }
        #     else{

        #         $final += [PSCustomObject]@{
        #             Domain = if ($user) { $userDomain } else { $groupDomain }
        #             Name = if ($user) { $user.Name } else { $grp.Name }
        #             SamAccountName = if ($user) { $user.SamAccountName } else { $grp.SamAccountName }
        #             ObjectClass = if ($user) { $user.ObjectClass } else { $grp.ObjectClass }
        #             MemberOf = if ($user) { Extract-GroupName $user.MemberOf -join ";" } else { Extract-GroupName $grp.MemberOf -join ";" }
        #             UserRight = [Collections.Generic.HashSet[string]]@($poname)
        #             LastLogonDate = if ($user.LastLogonDate) { $user.LastLogonDate } else { "Never" }
        #             AccountStatus = if ($user.Enabled) { If ($user.Enabled -eq 'True') { 'Active' } else { 'Disabled' } } else { "NA" }
        #             SourceOfRight = [Collections.Generic.HashSet[string]]@("self")
        #         }

        #     }




        # }
        function Get-GroupMemberRecursively {
            param($identity,[String]$domain)
            $members = @()
            $subgrp = @()

            $members += (Get-ADGroup -Identity "$($identity.SamAccountName)" -Server $domain -Properties Member).Member |Get-ADUser -Server $domain -Properties MemberOf,Enabled,LastLogonDate -ErrorAction SilentlyContinue
            $subgrp += (Get-ADGroup -Identity "$($identity.SamAccountName)" -Server $domain -Properties Member).Member |Get-ADGroup -Server $domain -Properties SamAccountName -ErrorAction SilentlyContinue
            
            while ($subgrp){
                
                $tmp = $subgrp
                $subgrp = @()
                foreach ($m in $tmp) {
                    foreach ($subdomain in $domains){
                        $trialGroup = Get-ADGroup -Filter "SID -like '$($m.SID)'" -Server $subdomain -Properties Member
                        # Write-Host $trialGroup.Member
                        if ($trialGroup){
                            foreach ($eachMember in $trialGroup.Member){
                                foreach ($innerdomain in $domains){
                                    $testobject = Get-ADUser -Filter "DistinguishedName -like '$eachMember'" -server $innerdomain -Properties MemberOf,Enabled,LastLogonDate -ErrorAction SilentlyContinue
                                    if ($testobject){
                                        $members +=$testobject
                                    }
                                    
                                    $testobject= Get-ADGroup -Filter "DistinguishedName -like '$eachMember'" -Server $innerdomain -Properties SamAccountName -ErrorAction SilentlyContinue
                                    if ($testobject){

                                        $existingEntry = Check-Existence $testobject $innerdomain
                                        if ($existingEntry){
                                            $existingEntry.UserRight.add($poname) |Out-Null
                                            $existingEntry.SourceOfRight.add($identity.SamAccountName) | Out-Null
                                        }           
                                        else{
                                            
                                            $final += [PSCustomObject]@{
                                                Domain = $innerdomain
                                                Name = $testobject.Name
                                                SamAccountName = $testobject.SamAccountName
                                                ObjectClass = $testobject.ObjectClass
                                                MemberOf =  Extract-GroupName $testobject.MemberOf -join ";"
                                                UserRight = [Collections.Generic.HashSet[string]]@($poname)
                                                LastLogonDate = "Never" 
                                                AccountStatus =  "NA" 
                                                SourceOfRight = [Collections.Generic.HashSet[string]]@($identity.SamAccountName)
                                            }
                            
                                        }




                                        $subgrp += $testobject
                                    }
                                }
                            }
                            break
                        }

                    }
                    # $members += (Get-ADGroup -Identity "$($m.SamAccountName)" -Server $domain -Properties Member).Member |Get-ADUser -Server $domain -Properties MemberOf,Enabled,LastLogonDate -ErrorAction SilentlyContinue
                    # $subgrp += (Get-ADGroup -Identity "$($m.SamAccountName)" -Server $domain -Properties Member).Member |Get-ADGroup -Server $domain -Properties SamAccountName -ErrorAction SilentlyContinue							
                }
            }

            return $members
        }

        if ($groups.group.count){
            
            for ($i=0; $i -lt $groups.group.count;$i = $i+1){
                if ($groups.group.count -ne $groups.domains.count){
                    Write-Host "group and domain length not match!"
                }


                # $domain = ($groups.domains[$i] | Out-String).Trim()
                $members = @()
                # try{
                #     $members += (Get-ADGroupMember -Identity "$($groups.group[$i].SamAccountName)" -server $groups.domains[$i] -Recursive)|
                #     Where-Object { $_.ObjectClass -match "user" } |
                #     Get-ADUser -Server $groups.domains[$i] -Properties MemberOf, Enabled, LastLogonDate, DistinguishedName -ErrorAction SilentlyContinue
                # }
                # catch{
                    $members += Get-GroupMemberRecursively $groups.group[$i] $groups.domains[$i]
                # }
                foreach ($member in $members) {
                    $memberDomain = Extract-DomainFromDN $member.DistinguishedName
                    $existingEntry = Check-Existence $member $memberDomain
                    if ($existingEntry){
                        #this group has been processed before
                        $existingEntry.UserRight.add($poname) |Out-Null
                        $existingEntry.SourceOfRight.add("$($grp.Name)") | Out-Null
                    }
                    else{
    
                        $final += [PSCustomObject]@{
                            Domain = $memberDomain
                            Name = $member.Name
                            SamAccountName = $member.SamAccountName
                            ObjectClass = $member.ObjectClass
                            MemberOf = Extract-GroupName $member.MemberOf -join ";"
                            UserRight = [Collections.Generic.HashSet[string]]@($poname)
                            LastLogonDate = if ($member.LastLogonDate) { $member.LastLogonDate } else { "Never" }
                            AccountStatus = if ($member.Enabled) { If ($member.Enabled -eq 'True') { 'Active' } else { 'Disabled' } } else { "NA" }
                            SourceOfRight = [Collections.Generic.HashSet[string]]@($groups.group[$i].SamAccountName)
                        }
                    }
    
                }




            }
        }





        # # Expand all the AD group members
        # if ($grp) {
        #     $members = @()
        #     foreach ($domain in $domains) {
        #         try {
        #             try{

        #             $members += (Get-ADGroupMember -Identity "$($grp.SamAccountName)" -Server $domain -Recursive) |
        #                         Where-Object { $_.ObjectClass -match "user" } |
        #                         Get-ADUser -Server $domain -Properties MemberOf, Enabled, LastLogonDate, DistinguishedName 
        #             }
        #             catch{
        #             $members += Get-GroupMemberRecursively $grp $domain
        #             }

        #         } catch {
        #             Write-Host "Error retrieving members for group: $($grp.SamAccountName) in domain: $domain - $_"
        #         }
        #     }

        #     foreach ($member in $members) {
        #         $memberDomain = Extract-DomainFromDN $member.DistinguishedName
        #         $existingEntry = Check-Existence $member $memberDomain
        #         if ($existingEntry){
        #             #this group has been processed before
        #             $existingEntry.UserRight.add($poname) |Out-Null
        #             $existingEntry.SourceOfRight.add("$($grp.Name)") | Out-Null
        #         }
        #         else{

        #             $final += [PSCustomObject]@{
        #                 Domain = $memberDomain
        #                 Name = $member.Name
        #                 SamAccountName = $member.SamAccountName
        #                 ObjectClass = $member.ObjectClass
        #                 MemberOf = Extract-GroupName $member.MemberOf -join ";"
        #                 UserRight = [Collections.Generic.HashSet[string]]@($poname)
        #                 LastLogonDate = if ($member.LastLogonDate) { $member.LastLogonDate } else { "Never" }
        #                 AccountStatus = if ($member.Enabled) { If ($member.Enabled -eq 'True') { 'Active' } else { 'Disabled' } } else { "NA" }
        #                 SourceOfRight = [Collections.Generic.HashSet[string]]@($grp.SamAccountName)
        #             }
        #         }

        #     }
        # }
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
