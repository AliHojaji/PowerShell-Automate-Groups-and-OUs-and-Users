#--- Author : Ali Hojaji ---#

#--*------------------------*--#
#---> Groups & OUs & Users <---#
#--*------------------------*--#

#--> Create a new OU
New-ADOrganizationlUnit -Name FL-Sales -Path "DC=TEST,DC=LOCAL"

#--> Create usere in the new OU
New-ADUser -Name "User1" -SamAccountName USER1 -Path "OU=FL-SALES,DC=TEST,DC=LOCAL"
New-ADUser -Name "User2" -SamAccountName USER2 -Path "OU=FL-SALES,DC=TEST,DC=LOCAL"
New-ADUser -Name "User3" -SamAccountName USER3 -Path "OU=FL-SALES,DC=TEST,DC=LOCAL"

#--> Create a new group in the new OU
New-ADGroup -Name "FL-Sales-AcctOp" -SamAccountName FL-Sales-AcctOp -GroupCategory Security -GroupScope DomainLocal -Path "OU=FL-SALES,DC-TEST,DC=LOCAL"

#--> Create a new user
New-ADUser -Name "username" -GivenName "user firstname" -Surname "user lastname" -DisplayName "user displayname" -SamAccountName "username" -UserPrincipalName "username@domain.com" -AccountPassword (ConvertTo-SecureString "password" -AsPlainText -Force) -Enabled $true

#--> Add users to the group
Add-ADGroupMember FL-Sales-AcctOp USER1,USER2,USER3

#--> Enumerate the group
Get-ADGroupMember FL-Sales-AcctOp


#--> Create local User <--#
New-LocalUser -Name "username" -Description "user description" -FullName "user full name" -Password (ConvertTo-SecureString "password" -AsPlainText -Force)
