// Kronagent Azure Zero-Key Cross-Account Onboarding Template (Bicep)
// Deploys Read-Only (Observe) and Remediation (Contain) Service Principals with Federated Identity Credentials.

@description('The tenant ID of the Kronagent deployment platform.')
param kronagentTenantId string

@description('The external ID issued to the customer tenant for zero-key trust.')
param externalId string

resource observeRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  name: 'acdd72a7-3385-48ef-bd42-f606fba81ae7' // Reader role
}

resource containRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  name: 'b24988ac-6180-42a0-ab88-20f7382dd24c' // Contributor role
}

output observeRoleId string = observeRole.id
output containRoleId string = containRole.id
output externalIdValue string = externalId
