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
    [String[]] $NamedLocationsForSecurityRegistration = @("Allowed to register security info"),

    [Parameter(Mandatory=$false)]
    [Boolean] $DeleteUnknownPolicies = $false
)

Begin {
    <#
    .Synopsis
        Helper method to wrap Compare-Object with null support
    .DESCRIPTION
        Helper method to wrap Compare-Object with null support
    .EXAMPLE
        Compare-Value "yes" $null
    #>
    function Compare-Value {
        [CmdletBinding()]

        param (
            [Parameter(Mandatory=$false)]
            $ReferenceObject,

            [Parameter(Mandatory=$false)]
            $DifferenceObject,

            [Parameter(Mandatory=$false)]
            [Boolean] $Serialize = $false
        )

        Process {
            if($null -eq $ReferenceObject -or $null -eq $DifferenceObject) {
                return $ReferenceObject -ne $DifferenceObject
            } else {
                if($Serialize) {
                    Compare-Object (ConvertTo-Json -InputObject $ReferenceObject -Depth 20 -Compress) (ConvertTo-Json -InputObject $DifferenceObject -Depth 20 -Compress)
                } else {
                    Compare-Object $ReferenceObject $DifferenceObject
                }                
            }
        }
    }
}

Process {
    $Error.Clear()
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
    $allNamedLocations = Get-MgIdentityConditionalAccessNamedLocation
    $namedLocations = New-Object System.Collections.ArrayList
    $NamedLocationsForSecurityRegistration | 
        ForEach-Object {
            $namedLocation = $allNamedLocations | Where-Object displayName -eq $_
            if($namedLocation) {
                $namedLocations.Add($namedLocation.Id) | Out-Null
            } else {
                Write-Error "No named location called '$_', please create in the Azure Portal, under Azure Active Directory -> Security -> Conditional Access -> Named locations. This is used for determining which countries are acceptable for users to be in, when they self service register for SSPR and MFA." -ErrorAction Stop
            }
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
                $policy.conditions.locations.excludeLocations = $namedLocations
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
            Write-Host "Creating CA policy '$($_.displayName)'"
            if($PSCmdlet.ShouldProcess("Creating CA policy '$($_.displayName)'")){
                $result = Invoke-MgGraphRequest -Method Post -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Body ($_ | ConvertTo-Json -Depth 10) -ContentType "application/json"
                Write-Host "CA policy '$($_.displayName)' was created with id $($result.Id)"
            } else {
                Write-Host "WhatIf enabled, here is the content of the policy:"
                ($_ | ConvertTo-Json -Depth 10) | Write-Host
            }
        }

    
    #
    # Update CA policies that exists and require update
    #

    $policiesToDeploy |
        Where-Object displayName -in $conditionalAccessPolicies.displayName |
        ForEach-Object {
            $conditionalAccessPolicy = $conditionalAccessPolicies | Where-Object displayName -eq $_.displayName
            
            $needsUpdate = 
                (Compare-Value $_.state $conditionalAccessPolicy.state) -or
                (Compare-Value $_.conditions.applications.excludeApplications $conditionalAccessPolicy.conditions.applications.excludeApplications) -or
                (Compare-Value $_.conditions.applications.includeApplications $conditionalAccessPolicy.conditions.applications.includeApplications) -or
                (Compare-Value $_.conditions.applications.includeUserActions $conditionalAccessPolicy.conditions.applications.includeUserActions) -or
                (Compare-Value $_.conditions.users.excludeRoles $conditionalAccessPolicy.conditions.users.excludeRoles) -or
                (Compare-Value $_.conditions.users.includeRoles $conditionalAccessPolicy.conditions.users.includeRoles) -or
                (Compare-Value $_.conditions.users.excludeUsers $conditionalAccessPolicy.conditions.users.excludeUsers) -or
                (Compare-Value $_.conditions.users.includeUsers $conditionalAccessPolicy.conditions.users.includeUsers) -or
                (Compare-Value $_.conditions.users.excludeGroups $conditionalAccessPolicy.conditions.users.excludeGroups) -or
                (Compare-Value $_.conditions.users.includeGroups $conditionalAccessPolicy.conditions.users.includeGroups) -or
                (Compare-Value $_.conditions.locations.includeLocations $conditionalAccessPolicy.conditions.locations.includeLocations) -or
                (Compare-Value $_.conditions.locations.excludeLocations $conditionalAccessPolicy.conditions.locations.excludeLocations) -or
                (Compare-Value $_.conditions.userRiskLevels $conditionalAccessPolicy.conditions.userRiskLevels) -or
                (Compare-Value $_.conditions.platforms.excludePlatforms $conditionalAccessPolicy.conditions.platforms.excludePlatforms) -or
                (Compare-Value $_.conditions.platforms.includePlatforms $conditionalAccessPolicy.conditions.platforms.includePlatforms) -or
                (Compare-Value $_.conditions.clientAppTypes $conditionalAccessPolicy.conditions.clientAppTypes) -or
                (Compare-Value $_.conditions.signInRiskLevels $conditionalAccessPolicy.conditions.signInRiskLevels) -or
                (Compare-Value $_.grantControls.termsOfUse $conditionalAccessPolicy.grantControls.termsOfUse) -or
                (Compare-Value $_.grantControls.builtInControls $conditionalAccessPolicy.grantControls.builtInControls) -or
                (Compare-Value $_.grantControls.operator $conditionalAccessPolicy.grantControls.operator) -or
                (Compare-Value $_.grantControls.customAuthenticationFactors $conditionalAccessPolicy.grantControls.customAuthenticationFactors) -or
                (Compare-Value $_.sessionControls.persistentBrowser $conditionalAccessPolicy.sessionControls.persistentBrowser -Serialize:$true) -or
                (Compare-Value $_.sessionControls.signInFrequency $conditionalAccessPolicy.sessionControls.signInFrequency -Serialize:$true) -or
                (Compare-Value $_.sessionControls.persistentBrowser $conditionalAccessPolicy.sessionControls.persistentBrowser -Serialize:$true) -or
                (Compare-Value $_.sessionControls.applicationEnforcedRestrictions $conditionalAccessPolicy.sessionControls.applicationEnforcedRestrictions -Serialize:$true) -or
                (Compare-Value $_.sessionControls.cloudAppSecurity $conditionalAccessPolicy.sessionControls.cloudAppSecurity -Serialize:$true)            
                
            if($needsUpdate) {
                Write-Host "Updating CA policy '$($_.displayName)'"
                if($PSCmdlet.ShouldProcess("Updating CA policy '$($_.displayName)'")){
                    Invoke-MgGraphRequest -Method Patch -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($conditionalAccessPolicy.Id)" -Body ($_ | ConvertTo-Json -Depth 10) -ContentType "application/json"
                } else {
                    Write-Host "WhatIf enabled, here is the content of the policy:"
                    ($_ | ConvertTo-Json -Depth 10) | Write-Host
                }
            }
        }

    Pop-Location

    if($Error) {
        Write-Host "Finished with errors"
    } else {
        Write-Host "Finished successfully"
    }
}