[CmdletBinding(SupportsShouldProcess=$true)]
Param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({$_ -like "*.onmicrosoft.com"})]
    [String] $Tenant,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String[]] $ExemptedAccounts,

    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [String] $NamedLocationForSecurityRegistration = "Allowed to register security info",

    [Parameter(Mandatory=$false)]
    [Boolean] $DeleteUnknownPolicies = $false
)

Process {
    Push-Location $PSScriptRoot

    #
    # Ensure Microsoft.Graph is installed
    #
    Write-Debug "Loading Microsoft.Graph module"
    $connectCommand = Get-Command Connect-MgGraph -ErrorAction SilentlyContinue

    if(!$connectCommand) {
        Write-Warning "Could not find Microsoft.Graph module, trying to install..."
        Install-Module Microsoft.Graph -Scope CurrentUser -ErrorAction Stop
    } else {
        $latest = Find-Module Microsoft.Graph 
        if($latest.Version -gt $connectCommand.Module.Version) {
            Write-Warning "Microsoft.Graph module version $($connectCommand.Module.Version) installed, trying to update to version $($latest.Version)"
            Update-Module Microsoft.Graph -ErrorAction Stop
        }
    }

    #
    # Ensure connection
    #

    Write-Verbose "Conecting to Microsoft Graph"
    $Result = Connect-MgGraph -Scopes "Application.Read.All", "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess", "User.Read.All" -TenantId $Tenant
    if($Result -ne "Welcome To Microsoft Graph!") {
        throw "Unable to connect to Microsoft Graph"
    }
    
    # 
    # Get exempted users
    # 
    
    $ExemptedUserObjects = $ExemptedAccounts | 
        ForEach-Object {
            $u = Get-MgUser -UserId $_ -ErrorAction Stop
            Write-Verbose "Found user for exemption - $($u.UserPrincipalName) with object id $($u.Id)"
            $u
        }

    #
    # Get named locations
    #
    $namedLocation = Get-MgIdentityConditionalAccessNamedLocation  | Where-Object displayName -eq $NamedLocationForSecurityRegistration
    if(!$namedLocation) {
        Write-Error "No named location called '$NamedLocationForSecurityRegistration', please create in the Azure Portal, under Azure Active Directory -> Security -> Conditional Access -> Named locations. This is used for determining which countries are acceptable for users to be in, when they self service register for SSPR and MFA." -ErrorAction Stop
    }

    #
    # Read policy json files
    #

    Write-Debug "Reading policy json files"
    $policiesToDeploy = Get-ChildItem ".\Policies\*.json" | 
        ForEach-Object {
            $policy = Get-Content -Raw -Path $_.FullName | ConvertFrom-Json -Depth 10
            
            # Add exempted users to all policies using grant controls
            if($policy.grantControls.builtInControls) {
                $policy.conditions.users.excludeUsers += $ExemptedUserObjects | Select-Object -ExpandProperty Id
            }

            if($policy.displayName -eq 'User action - Block register security info for all users when not in acceptable location') {
                $policy.conditions.locations.excludeLocations = @($namedLocation.Id)
            }

            $policy
        }
    
    #
    # Read CA policies from tenant
    #
    
    $conditionalAccessPolicies = Invoke-MgGraphRequest -Method Get -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" | Select-Object -ExpandProperty Value

    # Print warnings for CA policies not in the json files
    $conditionalAccessPolicies | 
        Where-Object displayName -notin $policiesToDeploy.displayName |
        ForEach-Object {
            if($DeleteUnknownPolicies) {
                if($PSCmdlet.ShouldProcess("Deleting CA policy '$($_.displayName)'")){
                    Write-Host "Deleting CA policy '$($_.displayName)'"
                    Invoke-MgGraphRequest -Method Delete -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($_.Id)"
                }
            } else {
                Write-Warning "CA policy present in tenant: '$($_.displayName)', please clean up (Run this script with parameter -DeleteUnknownPolicies:`$true to delete unknown policies)"
            }
        }

    #
    # Create CA policies that does not exist
    #

    $policiesToDeploy |
        Where-Object displayName -notin $conditionalAccessPolicies.displayName |
        ForEach-Object {
            if($PSCmdlet.ShouldProcess("Creating CA policy '$($_.displayName)'")){
                Write-Verbose "Creating CA policy '$($_.displayName)'"
                $result = Invoke-MgGraphRequest -Method Post -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Body ($_ | ConvertTo-Json -Depth 10) -ContentType "application/json"
                Write-Host "CA policy '$($_.displayName)' was created with id $($result.Id)"
            }
        }

    
    #
    # Update CA policies that exists and require update
    #

    $policiesToDeploy |
        Where-Object displayName -in $conditionalAccessPolicies.displayName |
        ForEach-Object {
            $conditionalAccessPolicy = $conditionalAccessPolicies | Where-Object displayName -eq $_.displayName
            
            if($PSCmdlet.ShouldProcess("CA policy '$($_.displayName)' already exists with id '$($conditionalAccessPolicy.Id)', ensuring that it is correct (comparing is a nightmare)")){
                Write-Verbose "CA policy '$($_.displayName)' already exists with id '$($conditionalAccessPolicy.Id)', ensuring that it is correct (comparing is a nightmare)"
                Invoke-MgGraphRequest -Method Patch -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($conditionalAccessPolicy.Id)" -Body ($_ | ConvertTo-Json -Depth 10) -ContentType "application/json"
            }
        }

    Pop-Location
}