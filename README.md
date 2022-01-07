# Table of Contents

- [Overview](#automation-account-runbook-and-authentiation)
  - [Managed Identity](#managed-identity)
  - [Runas Connection](#runas-connection)
  - [Saved Credentials](#saved-credentials)
  - [Hybrid Runbook Worker](#hybrid-runbook-worker)
  
# Automation Account Runbook and Authentiation
This repository is built to host the sample scripts (mostly PowerShell) when you test Azure Automation Account - Runbook authentication options.
## Managed Identity
Using managed identity could let us to get the credential/token from runbook passwordless. The detailed instructions can be found from Azure public doc location below:

System: https://docs.microsoft.com/en-us/azure/automation/enable-managed-identity-for-automation

User: https://docs.microsoft.com/en-us/azure/automation/add-user-assigned-identity

$env:IDENTITY_ENDPOINT for runbook (sandbox) is: http://127.0.0.1:40037/oauth2/token

### System Assigned
```
'===== connect azure with az module'
$AzureContext = (Connect-AzAccount -Identity).Context
$AzureContext

# set context
$AzureContext = Set-AzContext -SubscriptionName $AzureContext.Subscription -DefaultProfile $AzureContext

'===== get token without az module'
$resource= "?resource=https://management.azure.com/" 
$url = $env:IDENTITY_ENDPOINT + $resource 
$Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]" 
$Headers.Add("X-IDENTITY-HEADER", $env:IDENTITY_HEADER) 
$Headers.Add("Metadata", "True") 
$accessToken = Invoke-RestMethod -Uri $url -Method 'GET' -Headers $Headers
Write-Output $accessToken.access_token

'===== get azure resource'
Get-AzResource | Select-Object ResourceId
```
### User Assgined
```
# user managed identity requires account id / client_id specified
$clientId = "guid" # object id of user assgined managed identity

'===== connect azure with az module'
$AzureContext = (Connect-AzAccount -Identity -AccountId $clientId).Context
$AzureContext

# set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureContext.Subscription -DefaultProfile $AzureContext

'===== get token without az module'
$resource= "?resource=https://management.azure.com/" 
$client_id="&client_id=$clientId"
$url = $env:IDENTITY_ENDPOINT + $resource + $client_id 
$Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]" 
$Headers.Add("X-IDENTITY-HEADER", $env:IDENTITY_HEADER) 
$Headers.Add("Metadata", "True") 
$accessToken = Invoke-RestMethod -Uri $url -Method 'GET' -Headers $Headers
Write-Output $accessToken.access_token

'===== get azure resources'
Get-AzResource | Select-Object ResourceId
```
## Runas Connection
Creating a new runas connection will do following tasks:
- Creates an Azure AD security principal 
- Generate a self signed cert and attach to SP
- Grant Contributor role on subscription level
- Fill the information above (New-AzAutomationConnection)

The detailed steps can be read from the manual PowerShell script: https://github.com/azureautomation/runbooks/blob/master/Utility/AzRunAs/Create-RunAsAccount.ps1

To get authenticated from runbook:
```
"===== get connection inside this automation account"
$conn = Get-AutomationConnection -Name "AzureRunAsConnection"

$conn
"object type: " + $conn.GetType().Name

"`n===== connect azure resource managment"
$azProfile = Connect-AzAccount -Tenant $conn.TenantID `
    -ApplicationId $conn.ApplicationID `
    -CertificateThumbprint $conn.CertificateThumbprint `
    -ServicePrincipal
$azProfile 

"`n===== get azure resource group "
Get-AzResourceGroup | Select-Object ResourceId

"`n===== connect azure active directory"
$aadContext = Connect-AzureAD -TenantId $conn.TenantID `
    -ApplicationId $conn.ApplicationID `
    -CertificateThumbprint $conn.CertificateThumbprint 
$aadContext

"`n===== get domains in aad"
Get-AzureADDomain | Select-Object Name
```
### Export AzureRunAsCertificate 
The certificate created by runas connection is exportable via runbook script below.
```
# provide automation account connection name, storage account, and pfx password
$connectionName = "AzureRunAsConnection"
$storageAccountResourceGroupName = "sa_rg_name"
$storageAccountName = "sa_name"
$storageContainer = "sa_container_name"
$pfxPassword = "P@ssword01!"

$conn = Get-AutomationConnection -Name $connectionName         

"=== log into azure"
Connect-AzAccount `
    -ServicePrincipal `
    -Tenant $conn.TenantId `
    -ApplicationId $conn.ApplicationId `
    -CertificateThumbprint $conn.CertificateThumbprint 

$runasCert = Get-AutomationCertificate -Name "AzureRunAsCertificate"

"=== cert info"
$runasCert

# location to store certificate in the sandbox machine
# sample: C:\Users\Client\Temp\AzureRunAsCertificate.pfx
$pfxPath = ($env:temp + "\AzureRunAsCertificate.pfx")

"=== export cert to $pfxPath"
# export the certificate with password
$pfxCert = $runasCert.Export("pfx", $pfxPassword)
Set-Content -Value $pfxCert -Path $pfxPath -Force -Encoding Byte

"=== export pfx to storage blob"
$storageAccount = Get-AzStorageAccount -ResourceGroupName $storageAccountResourceGroupName -Name $storageAccountName
Set-AzStorageBlobContent -File $pfxPath -Container $storageContainer `
  -Blob "AzureRunAsCertificate.pfx" -Context $storageAccount.Context
```

Download this certficate from the target Storage Account, and import it into local machine (import to User - Personal store), use dir Cert:\CurrentUser\My to get the thumbprint or verify it from Azure Portal | Automation Account | Shared Resource - Certificates. Then we are able to call Az module using this certificate.

```
$servicePrincipalConnection = [PSCustomObject]@{
    TenantId              = 'tenant_id'
    ApplicationId         = 'app_id'
    CertificateThumbprint = 'thumbprint'
}

#$conn = Get-AutomationConnection -Name AzureRunAsConnection 
$conn = $servicePrincipalConnection
Connect-AzAccount -ServicePrincipal -Tenant $conn.TenantID `
    -ApplicationId $conn.ApplicationID `
    -CertificateThumbprint $conn.CertificateThumbprint

Get-AzContext -ListAvailable
```

## Saved Credentials
A common way to login Azure without actual user account is to use service principal + secret. The detailed steps of creating such service principal could be found at https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal#get-tenant-and-app-id-values-for-signing-in

To use the username (appid/client_id) and password (secret) saved in automation account, shared resource:
```
"===== get saved cred"
$cred = Get-AutomationPSCredential -Name "runasapp-demo-cred"
$cred
$tenant = Get-AutomationVariable -Name "runasapp-demo-tenant"

"`n===== connect azure using saved cred"
Connect-AzAccount -Credential $cred -Tenant $tenant -ServicePrincipal
Get-AzResourceGroup | Select-Object ResourceId

# Use following commands to test it locally
# $Credential=New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "clientid", ("secret" | ConvertTo-SecureString -AsPlainText -Force)
# Connect-AzAccount -Credential $Credential -Tenant "tenantid" -ServicePrincipal
```

## Hybrid Runbook Worker 

### Windows - PowerShell 5.1
By default, HRW on Windows runs the script using **nt authority\system**. You can change the context in HRW settings.
```
Param(
    [Parameter(Mandatory=$True)]
    [String]$UserName
)

"=== current user context"
$contextUsername = whoami #[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$contextUsername

# generate randome password
$randomPasswordPlainText = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 6 | % { [char]$_ })
$securePassword = $randomPasswordPlainText  | ConvertTo-SecureString -AsPlainText -Force

"=== creating new user with name $Username"
New-LocalUser -Name $Username -Password $securePassword -Description "created by $contextUsername"

"EOF"
```

### Linux - Python 2.6
HRW on Linux runs the script using **hweautomation**. Changing the context in HWR settings is **not** effective as Windows.
```
import sys
import os
import crypt
import random
import string
import getpass

username = str(sys.argv[1])
userContext = getpass.getuser()

print("=== running python with user context " + userContext)

passwordPlainText = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(6))
passwordEncrypted = crypt.crypt(passwordPlainText,"22")
cmdToRun = "useradd -p " + passwordEncrypted + " " + username + " -c usercreatedby_" + userContext
os.system(cmdToRun)
#print(cmdToRun)
print("=== user created with password " + passwordPlainText)
```
