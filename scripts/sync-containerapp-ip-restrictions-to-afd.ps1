[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$SubscriptionId,
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroup,
    [Parameter(Mandatory = $true)]
    [string[]]$ContainerAppName,
    [string]$Location = "eastus",
    [string]$ServiceTagName = "AzureFrontDoor.Backend",
    [string]$RuleNamePrefix = "afd"
)

$ErrorActionPreference = "Stop"

function Get-AfdBackendIpv4Prefixes {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceTagLocation,
        [Parameter(Mandatory = $true)]
        [string]$TagName
    )

    $query = "values[?name=='$TagName'].properties.addressPrefixes[]"
    $prefixes = az network list-service-tags --location $ServiceTagLocation --query $query --output tsv
    if (-not $prefixes) {
        throw "No service-tag prefixes returned for $TagName in $ServiceTagLocation."
    }

    $ipv4Prefixes = $prefixes |
        Where-Object { $_ -match '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/' } |
        Sort-Object -Unique

    if (-not $ipv4Prefixes) {
        throw "No IPv4 prefixes were returned for $TagName in $ServiceTagLocation. Container Apps IP restrictions only accept IPv4 CIDRs."
    }

    return $ipv4Prefixes
}

function New-IpRestrictionRules {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Prefixes,
        [Parameter(Mandatory = $true)]
        [string]$Prefix,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $rules = @()
    for ($index = 0; $index -lt $Prefixes.Count; $index++) {
        $rules += @{
            name = ("{0}{1:d3}" -f $Prefix, ($index + 1))
            description = $Description
            ipAddressRange = $Prefixes[$index]
            action = "Allow"
        }
    }

    return $rules
}

function Get-ArmAccessToken {
    $token = az account get-access-token --resource https://management.azure.com/ --query accessToken --output tsv
    if (-not $token) {
        throw "Unable to acquire an Azure Resource Manager access token."
    }

    return $token.Trim()
}

function Set-ContainerAppIngressRestrictions {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ContainerApp,
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true)]
        [string]$BearerToken,
        [Parameter(Mandatory = $true)]
        [object[]]$Restrictions
    )

    $containerAppId = az containerapp show --name $ContainerApp --resource-group $ResourceGroupName --query id --output tsv
    if (-not $containerAppId) {
        throw "Unable to resolve the Container App resource ID for $ContainerApp."
    }

    $uri = "https://management.azure.com$($containerAppId.Trim())?api-version=2026-01-01"
    $body = @{
        properties = @{
            configuration = @{
                ingress = @{
                    ipSecurityRestrictions = $Restrictions
                }
            }
        }
    } | ConvertTo-Json -Depth 8

    if ($PSCmdlet.ShouldProcess($ContainerApp, "Sync ingress allowlist with $($Restrictions.Count) Azure Front Door backend IPv4 prefixes")) {
        Invoke-RestMethod -Method Patch -Uri $uri -Headers @{ Authorization = "Bearer $BearerToken" } -ContentType "application/json" -Body $body | Out-Null

        [pscustomobject]@{
            containerApp = $ContainerApp
            ruleCount = $Restrictions.Count
            resourceGroup = $ResourceGroupName
        }
    }
}

if ($SubscriptionId) {
    az account set --subscription $SubscriptionId | Out-Null
}

$ipv4Prefixes = Get-AfdBackendIpv4Prefixes -ServiceTagLocation $Location -TagName $ServiceTagName
$ipRestrictions = New-IpRestrictionRules -Prefixes $ipv4Prefixes -Prefix $RuleNamePrefix -Description "Allow Azure Front Door backend"
$accessToken = Get-ArmAccessToken

foreach ($appName in $ContainerAppName) {
    Set-ContainerAppIngressRestrictions -ContainerApp $appName -ResourceGroupName $ResourceGroup -BearerToken $accessToken -Restrictions $ipRestrictions
}