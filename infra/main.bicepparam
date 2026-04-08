using 'main.bicep'

param environmentName = 'dev'
param location = 'eastus'
param approverEmail = 'security-team@example.com'
param openAiModelName = 'gpt-4o'
param allowedEgressFqdns = []
