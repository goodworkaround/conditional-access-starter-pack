# Conditional Access Starter Pack

This repository contains a simple script that can help you deploy a good baseline of Conditional Access Policies to your Azure AD tenant

## Prerequisites

- [PowerShell 7](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-windows?view=powershell-7.1)
- [Microsoft.Graph - will be installed automatically](https://www.powershellgallery.com/packages/Microsoft.Graph)
- A named location is created in Azure AD, named **Allowed to register security info**, used to determine which countries are acceptable for users to be located in when self service registering SSPR or MFA

![](media/namedlocation1.png)

## Usage

- Download or clone this repository to a computer with PowerShell 7
- Start pwsh.exe (or similar for Mac and Linux)
- Navigate to the folder where you downloaded this repository and run Deploy.ps1 with the following parameters

|-|-|-|
|Parameter|Type|Description|
|-|-|-|
|Tenant|String|The x.onmicrosoft.com tenant name of the tenant where you want to deploy the CA policies|
|ExemptedAccounts|String array|A list of users that will be exempted from policies blocking or requiring MFA or other grant|
|AllowedCountries|String array||

### Example

```PowerShell
.\Deploy.ps1 -Tenant "M365x843525.onmicrosoft.com" -ExemptedAccounts "AdeleV@M365x843525.OnMicrosoft.com","Admin@M365x843525.OnMicrosoft.com" -Verbose
```