using 'main.bicep'

param environmentName = 'dev'
param location = 'westus2'
param approverEmail = 'YOUR_EMAIL@example.com'
param allowedEgressFqdns = []
param aadClientId = readEnvironmentVariable('AAD_CLIENT_ID', '')
param deployerPrincipalId = readEnvironmentVariable('AZURE_PRINCIPAL_ID', '')
