function getUserRights {


	$final = @()

	$filteredRight = @() #in case if we want to filter away some right
	Write-Host "There are total of $((Get-ADUser -filter *).count) users and $((Get-ADGroup -filter *).count) groups"
	# Write-Host "Sanity check: should have $(((Get-ADGroup 'Domain Admins' -Properties Member)).Member.count)"
	# Write-Host "Sanity check: should have $(((Get-ADGroup 'Service Group Accounts' -Properties Member)).Member.count)"


	# export security setting 
	secedit /export /mergedpolicy /cfg securitysetting.txt
	$file = Get-Content securitysetting.txt		
	

	# extract privilege rights section
	# $policy = $file[([array]::IndexOf($file,"[Privilege Rights]")-$file.Count+1)..-1]

	# this version is made in case of there is no [Privilege Rights] in the file, but still have privileged defined.

	# first loop: handling Rights
	foreach ($po in $file){
		# extract the privilege name and corresponding list of SIDs
		#depends on the security policy format, [privilege rights] might not be the last part
		if ($po -match "="){
			$poname = ($po -split ' = ')[0]
			if($poname[0] -ne 's' -or $poname[1] -ne 'e'){continue}
			# if it is not related to privilege, just go next line
			$loop = (($po -split ' = ')[1]) -split ','
			if (-not $loop) {continue}
		}
		else{
			continue
			#continue for next line, until file end
		}

		if ($filteredRight -contains $poname){break}
		# second loop: handling each element of the Rights
		foreach ($ele in $loop){
				$user = ""
				$grp = ""
				if( $ele[0] -eq "*"){
					#it is a SID
					$user = Get-ADUser -Filter "SID -like '$($ele.Substring(1))'" -Properties Enabled,LastLogonDate,MemberOf
					$grp = (Get-ADGroup -Filter "SID -like '$($ele.SubString(1))'" -Properties MemberOf)
				
				}
				else{
					#not a SID, seems like custom editing on local group policy editor will append SamAccountName/CN/Name instead of the SID
					$user = Get-ADUser -Filter "SamAccountName -like '$ele'" -Properties Enabled,LastLogonDate,MemberOf
					if (-not $user){
						$user = Get-ADUser -Filter "CN -like '$ele'" -Properties Enabled,LastLogonDate,MemberOf
						if (-not $user){
							$user = Get-ADUser -Filter "Name -like '$ele'" -Properties Enabled,LastLogonDate,MemberOf
						}
					}
					$grp = (Get-ADGroup -Filter "SamAccountName -like '$ele'" -Properties MemberOf)
					if (-not $grp){
						$grp = (Get-ADGroup -Filter "CN -like '$ele'" -Properties MemberOf)
						if (-not $grp){
							$grp = (Get-ADGroup -Filter "Name -like '$ele'" -Properties MemberOf)
						}
					}

				}

				if ($user){ #this element is a user
					$existingEntry = $final|Where-Object {$_.SamAccountName -eq $user.SamAccountName}
					if($existingEntry){
						#this user has been fetched out before
						$existingEntry.userRight.add($poname) |Out-Null
						$existingEntry.source_of_right.add("self") | Out-Null
					
					}
					else{
						#new user
						
						$final += [PSCustomObject]@{
							name = $user.name
							SamAccountName = $user.SamAccountName
							objectClass = $user.ObjectClass
							memberof =   $user.MemberOf  | ForEach-Object {$_.Split(',')[0]} | ForEach-Object {$_.Split('=')[1]}
							userRight = [Collections.Generic.HashSet[string]]@($poname)
							lastLogonDate = if ($user.LastLogonDate) {$user.LastLogonDate} else {"Never"}
							AccountStatue = if ($user.Enabled) { If ($user.Enabled -eq 'True') {'Active'} else {'Disabled'}} else {"NA"}
							source_of_right = [Collections.Generic.HashSet[string]]@("self")
						}
					}
					continue
				}


				

				if ($grp){ #this element is a group
					
					if ($grp.SamAccountName -eq "Administrators"){
						
						continue}
					$existingEntry = $final|Where-Object {$_.SamAccountName -eq $grp.SamAccountName}
					if ($existingEntry){
						#this group has been processed before
						$existingEntry.userRight.add($poname) |Out-Null}
					
					else{
						#new group
						$final += [PSCustomObject]@{
							name = $grp.Name
							SamAccountName = $grp.SamAccountName
							objectClass = $grp.ObjectClass
							memberof =   if($grp.MemberOf) {$grp.MemberOf| ForEach-Object {$_.Split(',')[0]} | ForEach-Object {$_.Split('=')[1]}} else {""}
							userRight = [Collections.Generic.HashSet[string]]@($poname)
							lastLogonDate = "NA"
							AccountStatue = "NA"
							source_of_right = [Collections.Generic.HashSet[string]]@("self")
						}
					}
			
					#get all the users having the right of this group
					try{$members = (Get-ADGroupMember -Identity "$($grp.SamAccountName)" -Recursive ) |Where-Object {$_.ObjectClass -match "user"} |Get-ADUser -Properties MemberOf,Enabled,LastLogonDate}
					catch{
						$members = @()
						$subgrp = @()

						# Write-Host "$($grp.SamAccountName), this group has removed some user such that Get-ADGroupMember cannot be used, now use Get-ADGroup instead on this SID"
						try{
							$members += (Get-ADGroup -Identity "$($grp.SamAccountName)" -Properties Member).Member | Foreach-Object{
								try{
									Get-ADUser -filter "DistinguishedName -like '$_'" -Properties MemberOf,Enabled,LastLogonDate -errorAction SilentlyContinue
								}
								catch{}
							}
							$subgrp += (Get-ADGroup -Identity "$($grp.SamAccountName)" -Properties Member).Member | Foreach-Object{
								try{

									Get-ADGroup -filter "DistinguishedName -like '$_'" -Properties SamAccountName -errorAction SilentlyContinue
								}
								catch{}
							}

						while ($subgrp){
							
							$tmp = $subgrp
							$subgrp = @()
							foreach ($m in $tmp) {
								$members += (Get-ADGroup -Identity "$($m.SamAccountName)" -Properties Member).Member | Foreach-Object{
									try{

										Get-ADUser -filter "DistinguishedName -like '$_'" -Properties MemberOf,Enabled,LastLogonDate -errorAction SilentlyContinue
									}
									catch{}
								}
								$subgrp += (Get-ADGroup -Identity "$($m.SamAccountName)" -Properties Member).Member | Foreach-Object{
									try{
										Get-ADGroup -filter "DistinguishedName -like '$_'" -Properties SamAccountName -errorAction SilentlyContinue
									}
									catch{}
								}					
							}
						}
						}
						catch{
							continue
						# Write-Warning "seems like FSP is not able to workaround with this as well, let's flag this group - $(($grp.SamAccountName)) - for further investigation."
						}
					
					}
					
					#third loop: to process the member of the group
					foreach ($member in $members){
						$existingEntry = $final|Where-Object {$_.SamAccountName -eq $member.SamAccountName}
						if($existingEntry){
							#this user has been processed before
							$existingEntry.userRight.add($poname) |Out-Null
							$existingEntry.source_of_right.add($grp.Name) | Out-Null}

						else{
							#new user
							#get the user last login and interactive login and the status.
							$final += [PSCustomObject]@{
								name = $member.name
								SamAccountName = $member.SamAccountName
								objectClass = $member.ObjectClass
								# memberof =  $member.MemberOf | Get-ADGroup | Select-Object Name |Format-Table -HideTableHeaders
								memberof = $member.MemberOf| ForEach-Object {$_.Split(',')[0]} | ForEach-Object {$_.Split('=')[1]}
								userRight = [Collections.Generic.HashSet[string]]@($poname)
								lastLogonDate = if ($member.LastLogonDate) {$member.LastLogonDate} else {"Never"}
								AccountStatue = if ($member.Enabled) { If ($member.Enabled -eq 'True') {'Active'} else {'Disabled'}} else {"NA"}
								source_of_right = [Collections.Generic.HashSet[string]]@($grp.Name)
							}
						}
					}

				}
		}
		}	

	
	#turn memberof and userRight and source_of_right from list/set to string for export
	foreach ($f in $final){
		$f.memberof = $f.memberof | Out-String
		$f.userRight = $f.userRight | Out-String
		$f.source_of_right = $f.source_of_right | Out-String
	}
	Write-Host "Among them, there are $(($final|Where-Object {$_.objectClass -eq "user"}).count) privileged users and $(($final|Where-Object {$_.objectClass -eq "group"}).count) direct privileged groups"

	#export and cleanup

	$output = "PrivilegedUserAccounts.csv"
	$final | Export-Csv -Path $output -NoTypeInformation -Encoding UTF8
	rm ".\securitysetting.txt"
	return $final
}


getUserRights | Out-Null