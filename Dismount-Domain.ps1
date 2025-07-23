# Dismount-Domain
# Prompt for domain admin credentials
$domainAdminCred = Get-Credential -Message "Please enter the domain admin username and password"

# Remove computer from domain
Remove-Computer -UnjoinDomainCredential $domainAdminCred -Force -Restart
