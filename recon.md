# Recon

* [Manually](#Manually)
* [AADinternals](#AADinternals)
* [Microburst](#Microburst)
* [Valid emails](#Valid-emails)
* [RoadRecon](#ROADRecon)
* [AzureBound](#AzureBound)

### Manually
#### Get if tenant is in use and if fedaration is in use.
- Federation with Azure AD or O365 enables users to authenticate using on-premises credentials and access all resources in cloud.
```
https://login.microsoftonline.com/getuserrealm.srf?login=<USER>@<DOMAIN>&xml=1
https://login.microsoftonline.com/getuserrealm.srf?login=root@defcorphq.onmicrosoft.com&xml=1
```

#### Get the Tenant ID
```
https://login.microsoftonline.com/<DOMAIN>/.well-known/openid-configuration
https://login.microsoftonline.com/defcorphq.onmicrosoft.com/.well-known/openid-configuration
```

### AADinternals
https://github.com/Gerenios/AADInternals
https://o365blog.com/aadinternals/
#### Import the AADinternals module
```
import-module .\AADInternals.psd1
```

####  Get tenant name, authentication, brand name (usually same as directory name) and domain name
```
Get-AADIntLoginInformation -UserName <RANDOM USER>@<DOMAIN>
```

#### Get tenant ID
```
Get-AADIntTenantID -Domain <DOMAIN>
```

#### Get tenant domains
```
Get-AADIntTenantDomains -Domain <DOMAIN>
```

#### Get all the information
```
Invoke-AADIntReconAsOutsider -DomainName <DOMAIN>
```

## Microburst
#### Enumerate used services
- https://github.com/NetSPI/MicroBurst
- Edit the permutations.txt to add permutations such as career, hr, users, file and backup
```
Import-Module MicroBurst.psm1 -Verbose
Invoke-EnumerateAzureSubDomains -Base <SHORT DOMAIN NAME> -Verbose
```

#### Enumerate Azureblobs
- add permutations to permutations.txt like common, backup, code in the misc directory.
```
Import-Module ./Microburst.psm1
Invoke-EnumerateAzureBlobs -Base <SHORT DOMAIN> -OutputFile azureblobs.txt
```

## Valid emails
#### Check for Email ID's
- https://github.com/LMGsec/o365creeper
- Could gather list of emails from something like harvester or hunter.io or smth and validate them!
- admin, root, test, contact (try those default for exam)
```
python o365creeper.py -f list_of_emails.txt -o validemails.txt
```
- Possible to use https://github.com/nyxgeek/onedrive_user_enum (Non-lab-tool)

## ROADRecon

https://github.com/dirkjanm/ROADtools/wiki/Getting-started-with-ROADrecon
``` 
check ROADRecon 
```

## AzureBound
- referenece [cheatcheat](https://hausec.com/2020/11/23/azurehound-cypher-cheatsheet/)
- reference [AzureBound custom queries](/blob/main/customqueries.json) 
- reference [neoj4 console](/blob/main/neo4j%20console%20query)


## PowerZure

Getting Started
An overview of Azure, Azure AD, and PowerZure is covered in my blog post here https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a

To get started with PowerZure, make sure the requirements are met. If you do not have the Az Module, PowerZure will ask you if you’d like to install it automatically when importing PowerZure as a module. PowerZure does require an Administrative PowerShell window, >= version 5.0. There is no advantage to running PowerZure on a compromised/pwned machine. Since you’re interacting with the cloud, it’s opsec safe to use from a bastion operating host, or if you’re feeling adventurous, your own host. Read the operational usage page here

Additionally, you must sign-in to Azure before PowerZure functions are made available. To sign in, use the cmdlet

Connect-AzAccount
Once you are signed in to Azure, you can import PowerZure:

ipmo C:\Path\To\Powerzure.psd1
Upon importing, it will list your current role and available subscriptions. From there, you can run

Get-AzureTarget
To get a list of resources you have access to.

