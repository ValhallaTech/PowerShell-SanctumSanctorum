# Mount-Domain
# Declare domain name variable
$domainName = "wssu.edu"

# Prompt for domain admin credentials
$domainAdminCred = Get-Credential -Message "Please enter the domain admin username and password"

# Add computer to domain
Add-Computer -DomainName $domainName -Credential $domainAdminCred -Force -Restart
