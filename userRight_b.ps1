function getUserRights {


	$final = @()
	$usedElement = [System.Collections.Generic.HashSet[string]]@() #defined a set to make the element unique
	$filteredRight = @() #in case if we want to filter away some right
	Write-Host "There are total of $((Get-ADUser -filter *).count+(Get-ADGroup -filter *).count) users and groups"

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
					#not a SID, seems like custom editing on local group policy editor will append SamAccountName instead of the SID
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

				# if (-not $user -and -not $grp){
				# 	Write-Host "$ele does not appear as a user or a grp maybe it is a services or computers"
				# }

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
							memberof =   $user.MemberOf | Get-ADGroup | Select-Object Name|Format-Table -HideTableHeaders
							userRight = [Collections.Generic.HashSet[string]]@($poname)
							lastLogonDate = if ($user.LastLogonDate) {$user.LastLogonDate} else {"Never"}
							AccountStatue = if ($user.Enabled) { If ($user.Enabled -eq 'True') {'Active'} else {'Disabled'}} else {"NA"}
							source_of_right = [Collections.Generic.HashSet[string]]@("self")
						}
					}
					$usedElement.add($ele) | Out-Null	
					continue
				}


				

				if ($grp){ #this element is a group
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
							memberof =   if($grp.MemberOf) {$grp.MemberOf | Get-ADGroup | Select-Object Name |Format-Table -HideTableHeaders} else {""}
							userRight = [Collections.Generic.HashSet[string]]@($poname)
							lastLogonDate = "NA"
							AccountStatue = "NA"
							source_of_right = [Collections.Generic.HashSet[string]]@("self")
						}
						$usedElement.add($ele) |Out-Null
					}

					#get all the users having the right of this group
					try{a$members = (Get-ADGroupMember -Identity "$($grp.SamAccountName)" -Recursive ) |Where-Object {$_.ObjectClass -match "user"} |Get-ADUser -Properties MemberOf,Enabled,LastLogonDate}
					catch{
						Write-Host "$($grp.SamAccountName), this group has removed some user such that Get-ADGroupMember cannot be used, now use Get-ADGroup instead on this SID"
						try{
						$members = (Get-ADGroup -Identity "$($grp.SamAccountName)" -Properties Member).Member |Get-ADObject |Where-Object {$_.ObjectClass -match "user"} |Get-ADUser -Properties MemberOf,Enabled,LastLogonDate
						$subgrp = (Get-ADGroup -Identity "$($grp.SamAccountName)" -Properties Member).Member |Get-ADObject |Where-Object {$_.ObjectClass -match "group"} |Get-ADGroup
						foreach ($m in $subgrp) {
							$members += (Get-ADGroup -Identity "$($m.SamAccountName)" -Properties Member).Member |Get-ADObject |Where-Object {$_.ObjectClass -match "user"} |Get-ADUser -Properties MemberOf,Enabled,LastLogonDate
							$subgrp += (Get-ADGroup -Identity "$($m.SamAccountName)" -Properties Member).Member |Get-ADObject |Where-Object {$_.ObjectClass -match "group"} |Get-ADGroup
						}




						Write-Host "Success"
						}
						catch{
						Write-Host "seems like FSP is not able to workaround with this as well, let's flag this group for further investigation."
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
							#new new user
							#get the user last login and interactive login and the status.
							$final += [PSCustomObject]@{
								name = $member.name
								SamAccountName = $member.SamAccountName
								objectClass = $member.ObjectClass
								memberof =  $member.MemberOf | Get-ADGroup | Select-Object Name |Format-Table -HideTableHeaders
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
	Write-Host "Among them, there are $($final.count) privileged users and groups"

	#export and cleanup

	$output = "PrivilegedUserAccounts.csv"
	$final | Export-Csv -Path $output -NoTypeInformation -Encoding UTF8
	# rm ".\securitysetting.txt"

	return $final
}


getUserRights | Out-Null