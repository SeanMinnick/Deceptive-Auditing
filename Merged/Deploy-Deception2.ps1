#Requires –Modules ActiveDirectory

<#

File: Deploy-Deception.ps1
Author: Nikhil Mittal (@nikhil_mitt)
Modifications : Sean Minnick (@SeanMinnick)
Description: A PowerShell module to deploy active directory decoy objects.
Required Dependencies: ActiveDirectory Module by Microsoft
Link: https://github.com/SeanMinnick/Deceptive-Auditing/

#>


##################################### Helper Functions #####################################

function New-DecoyUser
{
<#
.SYNOPSIS
Create a user object.
 
.DESCRIPTION
Creates a user object on the domain. Must be run on a DC with domain admin privileges.

.PARAMETER UserFirstName
First name of the user to be crated. 

.PARAMETER UserLastName
Last name of the user to be crated. 

.PARAMETER Password
Password for the user to be created. 

.PARAMETER OUDistinguishedName
DistinguishedName of OU where the user will be created. The default User OU is used if this paramter is not specified.

.EXAMPLE
PS C:\> Create-DecoyUser -UserFirstName user -UserLastName manager -Password Pass@123
Use the above command to create a user 'usermanager'.

.LINK
https://www.labofapenetrationtester.com/2018/10/deploy-deception.html
https://github.com/samratashok/Deploy-Deception
#> 
    [CmdletBinding()] Param(
        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $UserFirstName,

        [Parameter(Position = 1, Mandatory = $False)]
        [String]
        $UserLastName,
        
        [Parameter(Position = 2, Mandatory = $False)]
        [String]
        $Password,
        
        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        $OUDistinguishedName
    )

        $UserDisplayName = $UserFirstName + $UserLastName
        Write-Verbose "Creating user $UserDisplayName."

        if (!$OUDistinguishedName)
        {
            Write-Verbose "Creating user $UserDisplayName."
            (New-ADUser -Name $UserDisplayName -AccountPassword (ConvertTo-SecureString -AsPlainText $Password -Force) -SamAccountName $UserDisplayName -Enabled $True -DisplayName $UserDisplayName -PassThru).SamAccountName
        }
        else
        {
            Write-Verbose "Creating user $UserDisplayName in $OUDistinguishedName."
            (New-ADUser -Name $UserDisplayName -AccountPassword (ConvertTo-SecureString -AsPlainText $Password -Force) -SamAccountName $UserDisplayName -Enabled $True -DisplayName $UserDisplayName -Path $OUDistinguishedName -PassThru).SamAccountName
        }

}

function New-DecoyComputer
{
<#
.SYNOPSIS
Create a computer object.
 
.DESCRIPTION
Creates a computer object on the domain. Must be run on a DC with domain admin privileges.

.PARAMETER ComputerName
Name of the computer to be crated. 

.PARAMETER OUDistinguishedName
DistinguishedName of OU where the computer will be created. The default Computer OU is used if this paramter is not specified.

.EXAMPLE
PS C:\> Create-DecoyComputer -ComputerName revert-web -Verbose
Use the above command to create a computer 'revert-web'.

.LINK
https://www.labofapenetrationtester.com/2018/10/deploy-deception.html
https://github.com/samratashok/Deploy-Deception
#> 
    [CmdletBinding()] Param(
        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $ComputerName,
             
        [Parameter(Position = 1, Mandatory = $False)]
        [String]
        $OUDistinguishedName
    )
        $DNSHostname = $ComputerName + "." + (Get-ADDomain).DNSRoot
        Write-Verbose "Creating computer $ComputerName."

        if (!$OUDistinguishedName)
        {
            Write-Verbose "Creating computer $DNSHostname."
            (New-ADComputer -Name $ComputerName -Enabled $True -DNSHostName $DNSHostname -PassThru).SamAccountName
        }
        else
        {
            Write-Verbose "Creating computer $DNSHostname in $OUDistinguishedName."
            (New-ADComputer -Name $ComputerName -Enabled $True -DNSHostName $DNSHostname -Path $OUDistinguishedName -PassThru).SamAccountName
        }

}

function New-DecoyGroup
{
<#
.SYNOPSIS
Create a Group object.
 
.DESCRIPTION
Creates a Group object on the domain. Must be run on a DC with domain admin privileges.

.PARAMETER GroupName
Name of the Group to be crated. 

.PARAMETER GroupScope
The scope of created group. Default is Global.

.EXAMPLE
PS C:\> Create-DecoyGroup -GroupName 'Forest Admins' -Verbose
Use the above command to create a Global Group 'Forest Admins'.

.LINK
https://www.labofapenetrationtester.com/2018/10/deploy-deception.html
https://github.com/samratashok/Deploy-Deception
#> 
    [CmdletBinding()] Param(
        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $GroupName,
             
        [Parameter(Position = 1, Mandatory = $False)]
        [String]
        [ValidateSet ("DomainLocal","Global","Universal")]
        $GroupScope = "Global"
    )
        Write-Verbose "Creating Group $GroupName."
        (New-ADGroup -Name $GroupName -GroupScope $GroupScope -PassThru).SamAccountName

}

function New-DecoyOU {
<#
.SYNOPSIS
Create a decoy Organizational Unit (OU).

.DESCRIPTION
Creates a new OU in Active Directory. Must be run on a Domain Controller or from a system with RSAT tools and appropriate privileges.

.PARAMETER OUName
Name of the OU to be created.

.PARAMETER ParentDistinguishedName
DistinguishedName of the parent OU or container where the new OU will be created. If not specified, the root of the domain is used.

.EXAMPLE
PS C:\> New-DecoyOU -OUName "DecoyServers" -Verbose
Creates a new OU named "DecoyServers" in the root of the domain.

.EXAMPLE
PS C:\> New-DecoyOU -OUName "DecoyWorkstations" -ParentDistinguishedName "OU=Departments,DC=example,DC=com" -Verbose
Creates a new OU under "OU=Departments,DC=example,DC=com".

.LINK
https://docs.microsoft.com/en-us/powershell/module/activedirectory/new-adorganizationalunit
#>
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true)]
        [string]$OUName,

        [Parameter(Position = 1, Mandatory = $false)]
        [string]$ParentDistinguishedName
    )

    try {
        if ($ParentDistinguishedName) {
            $OUPath = "OU=$OUName,$ParentDistinguishedName"
        } else {
            $domainDN = (Get-ADDomain).DistinguishedName
            $OUPath = "OU=$OUName,$domainDN"
        }

        Write-Verbose "Creating OU: $OUPath"
        New-ADOrganizationalUnit -Name $OUName -Path ($OUPath -replace "^OU=.*?,") -ProtectedFromAccidentalDeletion $true
        Write-Output "OU '$OUName' created successfully at '$OUPath'"
    }
    catch {
        Write-Error "Failed to create OU: $_"
    }
}

function New-DecoyGPO {
    <#
    .SYNOPSIS
    Creates a decoy Group Policy Object and makes it attractive to attackers.

    .DESCRIPTION
    Creates a GPO and optionally:
    - Links it to an OU
    - Grants GpoRead permissions to "Authenticated Users"
    - Sets an optional GPO comment

    .PARAMETER Name
    Name of the decoy GPO.

    .PARAMETER Comment
    Optional text comment to assign to the GPO (visible in GPMC).

    .PARAMETER TargetOU
    Distinguished Name (DN) of the OU to link the GPO to.

    .PARAMETER MakeReadable
    If set, grants GpoRead to "Authenticated Users" for enumeration bait.

    .EXAMPLE
    New-DecoyGPO -Name "PrivilegedAccessBackup" -Comment "Legacy GPO for admin access" -TargetOU "OU=Decoys,DC=domain,DC=com" -MakeReadable
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [string]$Comment = $null,

        [Parameter(Mandatory = $false)]
        [string]$TargetOU,

        [switch]$MakeReadable
    )

    try {
        New-GPO -Name $Name | Out-Null
        Start-Sleep -Seconds 2
        $gpo = Get-GPO -Name $Name -ErrorAction Stop

        if ($Comment) {
            (Get-GPO -Guid $gpo.Id).Description = $Comment
            Write-Verbose "Set GPO comment: $Comment"
        }

        Write-Verbose "Created GPO: $($gpo.DisplayName) [$($gpo.Id)]"

        if ($TargetOU) {
            Start-Sleep -Seconds 2
            $gpoCheck = Get-GPO -Name $Name -ErrorAction Stop
            if ($gpoCheck) {
                New-GPLink -Guid $gpo.Id -Target $TargetOU -LinkEnabled "Yes"
                Write-Verbose "Linked GPO to OU: $TargetOU"
            }
        }

        if ($MakeReadable) {
            Set-GPPermissions -Name $Name -TargetName "Authenticated Users" -TargetType Group -PermissionLevel GpoRead
            Write-Verbose "Granted GpoRead permissions to Authenticated Users"
        }

        return $gpo
    }
    catch {
        Write-Error "Failed to create or configure decoy GPO: $_"
    }
}



function Get-ADObjectDetails
{
<#
.SYNOPSIS
Helper function to retrieve details about an object from domain.
 
.DESCRIPTION
Helper function to retrieve details - SamAccountName, Distibguished Name and ACL for an object from domain.

.PARAMETER UserName
Username to get details for. 

.PARAMETER SamAccountName
SamAccountName of a user to get details for.

.PARAMETER DistinguisedName
DistinguishedName of a user to get details for. 

.PARAMETER ComputerName
ComputerName to get details for. 

.PARAMETER GroupName
GroupName to get details for. 

.PARAMETER OUName
OUName to get details for.

.EXAMPLE
PS C:\> Get-ADObjectDetails -SamAccountName usermanager.
Use the above command to get details for the user 'usermanager'.

.LINK
https://www.labofapenetrationtester.com/2018/10/deploy-deception.html
https://github.com/samratashok/Deploy-Deception
#> 

    [CmdletBinding()] Param(

        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $UserName,
        
        [Parameter(Position = 1, Mandatory = $False)]
        [String]
        $SAMAccountName,
        
        [Parameter(Position = 2, Mandatory = $False)]
        [String]
        $DistinguishedName,

        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        $ComputerName,

        [Parameter(Position = 4, Mandatory = $False)]
        [String]
        $GroupName,
        
        [Parameter(Position = 5, Mandatory = $False)]
        [String]
        $OUName
    )

    if ($UserName)
    {
        $objDN = (Get-ADUser -Filter {Name -eq $UserName}).distinguishedname
        $TargetSamAccountName = (Get-ADUser -Filter {Name -eq $UserName}).SamAccountName
    }
    elseif ($SAMAccountName)
    {
        $objDN = (Get-ADUser -Identity $SamAccountName).distinguishedname
        $TargetSamAccountName = $SAMAccountName
    }
    elseif ($DistinguishedName)
    {
        $objDN = $DistinguishedName
        $TargetSamAccountName = (Get-ADUser -Filter {Name -eq $UserName}).SamAccountName
    }
    elseif ($ComputerName)
    {
        $objDN = (Get-ADComputer -Identity $ComputerName).distinguishedname
        $TargetSamAccountName = (Get-ADComputer -Identity $ComputerName).SamAccountName
    }
    elseif ($GroupName)
    {
        $objDN = (Get-ADGroup -Identity $GroupName).distinguishedname
        $TargetSamAccountName = (Get-ADGroup -Identity $GroupName).SamAccountName
    }

    elseif ($OUName)
    {
        $objDN = (Get-ADOrganizationalUnit -Filter {Name -eq $OUName}).distinguishedname
        $TargetSamAccountName = (Get-ADOrganizationalUnit -Filter {Name -eq $OUName}).SamAccountName
    }
    else
    {
        Write-Output 'Cannot find the object.'
    }
    #Write-Verbose "Getting the existing ACL for $objDN."
    $ACL = Get-Acl -Path "AD:\$objDN"

    
    # A PSObject for returning properties

    $ObjectProperties = @{

        SamAccountName = $TargetSamAccountName
        DistinguishedName = $objDN
        ACL = $ACL

    }

    New-Object psobject -Property $ObjectProperties
}

function New-DynamicParam {
    param (
        [Parameter(Mandatory)][string]$Name,
        [array]$ValidateSetOptions,
        [switch]$Mandatory,
        [switch]$ValueFromPipeline,
        [switch]$ValueFromPipelineByPropertyName
    )

    $attrib = New-Object System.Management.Automation.ParameterAttribute
    $attrib.Mandatory = $Mandatory.IsPresent
    $attrib.ValueFromPipeline = $ValueFromPipeline.IsPresent
    $attrib.ValueFromPipelineByPropertyName = $ValueFromPipelineByPropertyName.IsPresent

    $collection = New-Object 'System.Collections.ObjectModel.Collection[System.Attribute]'
    $collection.Add($attrib)

    if ($ValidateSetOptions) {
        $validateSet = New-Object System.Management.Automation.ValidateSetAttribute($ValidateSetOptions)
        $collection.Add($validateSet)
    }

    $type = if ($Name -in @('Rights', 'AuditFlags')) { [array] } else { [string] }
    return New-Object System.Management.Automation.RuntimeDefinedParameter($Name, $type, $collection)
}

function Set-AuditRule {
    <#
    .SYNOPSIS
    Sets or removes an access control entry (ACE) on the SACL of a file, registry, or AD object.

    .DESCRIPTION
    This function supports auditing on various object types, including registry keys, files, and Active Directory objects.
    Parameters dynamically adapt based on the selected object type. Use -RemoveAuditing to remove existing audit entries.

    .EXAMPLE
    Set-AuditRule -RegistryPath 'HKLM:\Software\MyKey' -WellKnownSidType WorldSid -Rights ReadKey -InheritanceFlags None -PropagationFlags None -AuditFlags Success
    #>

    [CmdletBinding(DefaultParameterSetName = 'None')]
    param (
        [Parameter(Mandatory, ParameterSetName = 'Registry')]
        [ValidateScript({ Test-Path $_ })]
        [string]$RegistryPath,

        [Parameter(Mandatory, ParameterSetName = 'File')]
        [ValidateScript({ Test-Path $_ })]
        [string]$FilePath,

        [Parameter(Mandatory, ParameterSetName = 'AD')]
        [string]$AdObjectPath,

        [Parameter(Mandatory)]
        [ArgumentCompleter({
            param($CommandName, $ParameterName, $WordToComplete)
            [System.Security.Principal.WellKnownSidType].DeclaredMembers |
                Where-Object { $_.IsStatic } |
                Select-Object -ExpandProperty Name |
                Where-Object { $_ -like "$WordToComplete*" }
        })]
        [string]$WellKnownSidType,

        [Parameter(Mandatory = $false)]
        [bool]$RemoveAuditing = $false
    )

    DynamicParam {
        $paramOptions = @()
        $paramSet = $PSCmdlet.ParameterSetName

        switch ($paramSet) {
            'AD' {
                $paramOptions += @(
                    @{
                        Name = 'Rights'
                        Mandatory = $true
                        ValidateSetOptions = ([System.DirectoryServices.ActiveDirectoryRights]).DeclaredMembers | Where-Object IsStatic | Select-Object -ExpandProperty Name
                    },
                    @{
                        Name = 'InheritanceFlags'
                        Mandatory = $true
                        ValidateSetOptions = ([System.DirectoryServices.ActiveDirectorySecurityInheritance]).DeclaredMembers | Where-Object IsStatic | Select-Object -ExpandProperty Name
                    },
                    @{
                        Name = 'AuditFlags'
                        Mandatory = $true
                        ValidateSetOptions = ([System.Security.AccessControl.AuditFlags]).DeclaredMembers | Where-Object IsStatic | Select-Object -ExpandProperty Name
                    },
                    @{
                        Name = 'AttributeGUID'
                        Mandatory = $false
                    }
                )

                if ("AccountDomainAdminsSid", "AccountDomainUsersSid", "AccountEnterpriseAdminsSid" -contains $WellKnownSidType) {
                    $paramOptions = @(@{ Name = 'DomainSid'; Mandatory = $true }) + $paramOptions
                }
            }

            'Registry' {
                $paramOptions += @(
                    @{
                        Name = 'Rights'
                        Mandatory = $true
                        ValidateSetOptions = ([System.Security.AccessControl.RegistryRights]).DeclaredMembers | Where-Object IsStatic | Select-Object -ExpandProperty Name
                    }
                )
            }

            'File' {
                $paramOptions += @(
                    @{
                        Name = 'Rights'
                        Mandatory = $true
                        ValidateSetOptions = ([System.Security.AccessControl.FileSystemRights]).DeclaredMembers | Where-Object IsStatic | Select-Object -ExpandProperty Name
                    }
                )
            }
        }

        if ($paramSet -in 'Registry', 'File') {
            $paramOptions += @(
                @{
                    Name = 'InheritanceFlags'
                    Mandatory = $true
                    ValidateSetOptions = ([System.Security.AccessControl.InheritanceFlags]).DeclaredMembers | Where-Object IsStatic | Select-Object -ExpandProperty Name
                },
                @{
                    Name = 'PropagationFlags'
                    Mandatory = $true
                    ValidateSetOptions = ([System.Security.AccessControl.PropagationFlags]).DeclaredMembers | Where-Object IsStatic | Select-Object -ExpandProperty Name
                },
                @{
                    Name = 'AuditFlags'
                    Mandatory = $true
                    ValidateSetOptions = ([System.Security.AccessControl.AuditFlags]).DeclaredMembers | Where-Object IsStatic | Select-Object -ExpandProperty Name
                }
            )
        }

        $RuntimeParams = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        foreach ($p in $paramOptions) {
            $RuntimeParam = New-DynamicParam @p
            $RuntimeParams.Add($p.Name, $RuntimeParam)
        }
        return $RuntimeParams
    }

    begin {
        $PSBoundParameters.GetEnumerator() | ForEach-Object {
            Set-Variable -Name $_.Key -Value $_.Value -Scope Local
        }
    }

    process {
        try {
            $sid = if ($DomainSid) {
                New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]$WellKnownSidType, [System.Security.Principal.SecurityIdentifier]$DomainSid)
            } else {
                New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]$WellKnownSidType, $null)
            }

            switch ($PSCmdlet.ParameterSetName) {
                'AD' {
                    $AuditRuleObject = if ($AttributeGUID) {
                        New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
                            $sid, $Rights, $AuditFlags, [guid]$AttributeGUID, $InheritanceFlags, [guid]'00000000-0000-0000-0000-000000000000'
                        )
                    } else {
                        New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
                            $sid, $Rights, $AuditFlags, [guid]'00000000-0000-0000-0000-000000000000', $InheritanceFlags, [guid]'00000000-0000-0000-0000-000000000000'
                        )
                    }
                    $path = $AdObjectPath
                }

                'Registry' {
                    $AuditRuleObject = New-Object System.Security.AccessControl.RegistryAuditRule(
                        $sid, $Rights, $InheritanceFlags, $PropagationFlags, $AuditFlags
                    )
                    $path = $RegistryPath
                }

                'File' {
                    $AuditRuleObject = New-Object System.Security.AccessControl.FileSystemAuditRule(
                        $sid, $Rights, $InheritanceFlags, $PropagationFlags, $AuditFlags
                    )
                    $path = $FilePath
                }
            }

            $acl = Get-Acl -Path $path -Audit

            if ($RemoveAuditing) {
                Write-Verbose "Removing audit rule..."
                $removed = $acl.RemoveAuditRule($AuditRuleObject)
                if (-not $removed) {
                    Write-Warning "No matching audit rule was found to remove."
                }
            } else {
                Write-Verbose "Adding audit rule..."
                $acl.SetAuditRule($AuditRuleObject)
            }

            Set-Acl -Path $path -AclObject $acl
        } catch {
            Write-Error "Failed to set or remove audit rule: $_"
        }
    }
}



################################## End of Helper Functions #################################


function Deploy-UserDeception
{
<#
.SYNOPSIS
Deploys the specific decoy user to log Security Event 4662 when a specific Right is used against it.

.DESCRIPTION
This function sets up auditing when a specified Right is used by a specifed principal against the decoy user object.

The function must be run on a DC with domain admin privileges. There are multiple user attributes and flags
which can be set while deploying the decoy. These attributes and flags make the decoy interesting for an attacker. 
When a right, say, ReadProperty is used to access the decoy user, a Security Event 4662 is logged. 

Note that Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> DS Access - Audit Directory Service Access
Group Policy needs to be configured to enable 4662 logging. 

.PARAMETER DecoySamAccountName
SamAccountName of the decoy user.  

.PARAMETER DecoyDistinguishedName
DistinguishedName of the decoy user. 

.PARAMETER UserFlag
A decoy user property which would be 'interesting' for an attacker.

.PARAMETER PasswordInDescription
Leave a password in Description of the decoy user.

.PARAMETER SPN
Set 'interesting' SPN for the decoy user in the format servicename/host

.PARAMETER Principal
The Principal (user or group) for which auditing is turned on when they use Rights defined by the Right or GUID paramter.

.PARAMETER Right
Thr Right for which auditing is turned on when used by the principal specified with the Principal parameter.
Default is ReadProperty right.

.PARAMETER GUID
GUID for the property for which auditing is turned on when Princpal uses Right on the property.

.PARAMETER AuditFlag
Turn on Auditing for Success or Failure. Default is Success.

.PARAMETER RemoveAuditing
Remove previously added Auditing ACE.

.EXAMPLE
PS C:\> Create-DecoyUser -UserFirstName user -UserLastName manager -Password Pass@123 | Deploy-UserDeception -UserFlag PasswordNeverExpires -Verbose
Creates a decoy user whose password never expires and a 4662 is logged whenever ANY property of the user is read. Very verbose!

.EXAMPLE
PS C:\> Create-DecoyUser -UserFirstName user -UserLastName manager -Password Pass@123 | Deploy-UserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose
Creates a decoy user whose password never expires and a 4662 is logged whenever x500uniqueIdentifier - d07da11f-8a3d-42b6-b0aa-76c962be719a property of the user is read.

This property is not read by net.exe, WMI classes (like Win32_UserAccount) and ActiveDirectory module.
But LDAP based tools like PowerView and ADExplorer trigger the logging.

.EXAMPLE
PS C:\> Create-DecoyUser -UserFirstName user -UserLastName manager-control -Password Pass@123 | Deploy-UserDeception -UserFlag AllowReversiblePasswordEncryption -Right ReadControl -Verbose 
Creates a decoy user which has Allow Reverisble Password Encrpytion property set. 
A 4662 is logged whenever DACL of the user is read.

This property is not read by enumeration tools unless specifically DACL or all properties for the decoy user are force read.

.LINK
https://www.labofapenetrationtester.com/2018/10/deploy-deception.html
https://github.com/samratashok/Deploy-Deception
#>
    [CmdletBinding()] Param(
        
        [Parameter(ParameterSetName="SamAccountName",Position = 0, Mandatory = $False,ValueFromPipeline = $True)]
        [String]
        $DecoySamAccountName,
        
        [Parameter(ParameterSetName="ADSPath",Position = 1, Mandatory = $False)]
        [String]
        $DecoyDistinguishedName,

        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        [ValidateSet ("DoesNotRequirePreAuth","AllowReversiblePasswordEncryption","PasswordNeverExpires","TrustedForDelegation","TrustedToAuthForDelegation")]
        $UserFlag,

        [Parameter(Position = 4, Mandatory = $False)]
        [String]
        $PasswordInDescription,

        [Parameter(Position = 5, Mandatory = $False)]
        [String]
        $SPN,

        [Parameter(Position = 6, Mandatory = $False)]
        [String]
        $Principal = "Everyone",

        [Parameter(Position = 7, Mandatory = $False)]
        [String]
        [ValidateSet ("GenericAll","GenericRead","GenericWrite","ReadControl","ReadProperty","WriteDacl","WriteOwner","WriteProperty")]
        $Right = "ReadProperty",

        [Parameter(Position = 8, Mandatory = $False)]
        [String]
        $GUID,

        [Parameter(Position = 9, Mandatory = $False)]
        [String]
        [ValidateSet ("Success","Failure")]
        $AuditFlag = "Success",

        [Parameter(Mandatory = $False)]
        [Bool]
        $RemoveAuditing = $False
    )

    if($DecoySamAccountName)
    {
        $DecoySamAccountName = (Get-ADObjectDetails -SAMAccountName $DecoySamAccountName).SamAccountName
    }

    elseif ($DecoyDistinguishedName)
    {
        $DecoySamAccountName = (Get-ADObjectDetails -DistinguishedName $DecoyDistinguishedName).SamAccountName
    }

    else
    {
        Write-Output "No such decoy user found."
    }
    
    if ($UserFlag)
    {
        # Set the Deocy user account userflags.
        Write-Verbose "Adding $UserFlag to decoy user $DecoySamAccountName."
        switch($UserFlag)
        {
        
            "DoesNotRequirePreAuth"
            {
                Set-ADAccountControl -Identity $DecoySamAccountName -DoesNotRequirePreAuth $true
            }
            "AllowReversiblePasswordEncryption"
            {
                Set-ADAccountControl -Identity $DecoySamAccountName -AllowReversiblePasswordEncryption $true
            }
            "PasswordNeverExpires"
            {
                Set-ADAccountControl -Identity $DecoySamAccountName -PasswordNeverExpires $true
            }
            "TrustedForDelegation"
            {
                Set-ADAccountControl -Identity $DecoySamAccountName -TrustedForDelegation $true
            }
            "TrustedToAuthForDelegation"
            {
                Set-ADAccountControl -Identity $DecoySamAccountName -TrustedToAuthForDelegation $true
            }
        }
    }

    if ($PasswordInDescription)
    {
        # Be creative! For example, "User Password is July@2018 - Last used by Gary"
        Write-Verbose "Adding $PasswordInDescription for decoy user $DecoySamAccountName."
        Set-ADUser -Identity $DecoySamAccountName -Description $PasswordInDescription
    }

    if ($SPN)
    {
        Write-Verbose "Adding $SPN to decoy user $DecoySamAccountName."
        Set-ADUser -Identity $DecoySamAccountName -ServicePrincipalNames @{Add=$SPN}
    }

    $UserObject = Get-ADUser $DecoySamAccountName
    $AdObjectPath = "AD:$($UserObject.DistinguishedName)"
    Set-AuditRule -AdObjectPath $AdObjectPath -WellKnownSidType WorldSid -Rights $Right -InheritanceFlags None -AuditFlags $AuditFlag -AttributeGUID $GUID

  
}

function Deploy-PrivilegedUserDeception
{
<#
.SYNOPSIS
Deploys the specific decoy user and provide it high privileges (with protections) to make it interesting for an adversary.

.DESCRIPTION
This function deploys a decoy user which has high privileges like membership of the Domain Admins group. 

There are protections like DenyLogon to avoid abuse of these privileges. 

Note that Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> DS Access - Audit Directory Service Access
Group Policy needs to be configured to enable 4662 logging.

and 

Audit Kerberos Authentication Service for Failure needs to be enabled for 4768.

.PARAMETER DecoySamAccountName
SamAccountName of the decoy user.  

.PARAMETER DecoyDistinguishedName
DistinguishedName of the decoy user.

.PARAMETER Technique
The privilges for the decoy user. Currently, DomainAdminsMembership and DCSyncRights.

.PARAMETER Protection
Protection for avoiding abuse of the privileges. Currently, only DenyLogon is available.

.PARAMETER Principal
The Principal (user or group) for which auditing is turned on when they use Rights defined by the Right or GUID paramter.

.PARAMETER Right
Thr Right for which auditing is turned on when used by the principal specified with the Principal parameter.
Default is ReadControl right.

.PARAMETER GUID
GUID for the property for which auditing is turned on when Princpal uses Right on the property.

.PARAMETER AuditFlag
Turn on Auditing for Success or Failure. Default is Success.

.PARAMETER CreateLogon
Create a logon for the created decoyuser on the DC where the function is run. This helps in avoiding detection of the decoy
which relies on logoncount. A user profile is created on the DC when this parameter is used. 

.PARAMETER logonCount
Number of logonCount for the decoy user. Default is 1.

.PARAMETER RemoveAuditing
Remove previously added Auditing ACE.

.EXAMPLE
PS C:\> Create-DecoyUser -UserFirstName dec -UserLastName da -Password Pass@123 | Deploy-PrivilegedUserDeception -Technique DomainAdminsMemebership -Protection DenyLogon -Verbose
Create a decoy user named decda and make it a member of the Domain Admins group. As a protection against potential abuse,
Deny logon to the user on any machine. Please be aware that if another DA gets comprimised the DenyLogon setting can be removed.

If there is any attempt to use the user credentials (password or hashes) a 4768 is logged.

Any enumeration which reads DACL or all properties for the user will result in a 4662 logging. 

.EXAMPLE
PS C:\> Deploy-PrivilegedUserDeception -DecoySamaccountName decda -Technique DCSyncRights -Protection DenyLogon -Verbose
Use existing user decda and make provide it DCSyncRights. As a protection against potential abuse,
Deny logon to the user on any machine.

If there is any attempt to use the user credentials (password or hashes) a 4768 is logged.

Any enumeration which reads DACL or all properties for the user will result in a 4662 logging. 

.EXAMPLE
PS C:\> Create-DecoyUser -UserFirstName test -UserLastName da -Password Pass@123 | Deploy-PrivilegedUserDeception -Technique DomainAdminsMemebership -Protection DenyLogon -CreateLogon -Verbose 
Create a decoy user named decda and make it a member of the Domain Admins group. 
As a protection against potential abuse, Deny logon to the user on any machine.. 

To avoid detection of the decoy which relies on logoncount use the CreateLogon option which starts and stops a process as the
decoy user on the DC. A user profile is created on the DC when this parameter is used. 

If there is any attempt to use the user credentials (password or hashes) a 4768 is logged.

Any enumeration which reads DACL or all properties for the user will result in a 4662 logging. 
 
.LINK
https://www.labofapenetrationtester.com/2018/10/deploy-deception.html
https://github.com/samratashok/Deploy-Deception
#>
    [CmdletBinding()] Param(
        
        [Parameter(ParameterSetName="SamAccountName",Position = 0, Mandatory = $False,ValueFromPipeline = $True)]
        [String]
        $DecoySamAccountName,

        [Parameter(ParameterSetName="ADSPath",Position = 1, Mandatory = $False)]
        [String]
        $DecoyDistinguishedName,

        [Parameter(Position = 2, Mandatory = $False)]
        [String]
        [ValidateSet ("DomainAdminsMembership","DCSyncRights")]
        $Technique,

        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        [ValidateSet ("DenyLogon")]
        $Protection,

        [Parameter(Position = 4, Mandatory = $False)]
        [String]
        $Principal = "Everyone",

        [Parameter(Position = 5, Mandatory = $False)]
        [String]
        [ValidateSet ("GenericAll","GenericRead","GenericWrite","ReadControl","ReadProperty","WriteDacl","WriteOwner","WriteProperty")]
        $Right = "ReadControl",

        [Parameter(Position = 6, Mandatory = $False)]
        [String]
        $GUID,

        [Parameter(Position = 7, Mandatory = $False)]
        [String]
        [ValidateSet ("Success","Failure")]
        $AuditFlag = "Success",

        [Parameter(Mandatory = $False)]
        [Switch]
        $CreateLogon,

        [Parameter(Mandatory = $False)]
        [int]
        $logonCount = 1,

        [Parameter(Mandatory = $False)]
        [Bool]
        $RemoveAuditing = $False
    )

    if($DecoySamAccountName)
    {
        $DecoySamAccountName = (Get-ADObjectDetails -SAMAccountName $DecoySamAccountName).SamAccountName
    }

    elseif ($DecoyDistinguishedName)
    {
        $DecoySamAccountName = (Get-ADObjectDetails -DistinguishedName $DecoyDistinguishedName).SamAccountName
    }
    else
    {
        Write-Output "No such decoy user found."
    }


    if ($Technique)
    {
        # Set the Deocy user's interesting privileges.
        switch($Technique)
        {
            "DomainAdminsMembership"
            {
                # The user will actually be a part of the DA group but cannot logon.
                Write-Verbose "Adding $DecoySamAccountName to the Domain Admins Group."
                Add-ADGroupMember -Identity "Domain Admins" -Members $DecoySamAccountName
            }
            "DCSyncRights"
            {          
                # Replication Rights
                Write-Verbose "Providing DCSync permissions to $DecoySamAccountName."
                $DomainDN = (Get-AdDomain).DistinguishedName
                $ACL = Get-Acl "AD:\$DomainDN"
                $sid = New-Object System.Security.Principal.NTAccount($DecoySamAccountName)
                $objectGuidChangesAll = New-Object Guid 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
                $ACE = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',$objectGuidChangesAll)
                $ACL.AddAccessRule($ACE)
                Set-Acl "AD:\$DomainDN" -AclObject $ACL

                $ACL = Get-Acl "AD:\$DomainDN"
                $objectGuidChanges = New-Object Guid 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
                $ACE = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',$objectGuidChanges)
                $ACL.AddAccessRule($ACE)
                Set-Acl "AD:\$DomainDN" -AclObject $ACL
            }
        }
    }

    if ($Protection)
    {
        switch ($Protection)
        {
            "DenyLogon"
            {
                # Deny logon to user from anywhere by setting logon hours
                $Hours = New-Object byte[] 21
                $Hours[5] = 000; $Hours[8] = 000; $Hours[11] = 000; $Hours[14] = 000; $Hours[17] = 000;
                $Hours[6] = 0; $Hours[9] = 0; $Hours[12] = 0; $Hours[15] = 0; $Hours[18] = 0;
                $ReplaceHashTable = New-Object HashTable
                $ReplaceHashTable.Add("logonHours", $Hours)
                Write-Verbose "Adding protection - Decoy user $DecoySamAccountName has been denied logon."
                Set-ADUser -Identity $DecoySamAccountName -Replace $ReplaceHashTable
            }
        }
    }

    $UserObject = Get-ADUser $DecoySamAccountName
    $AdObjectPath = "AD:$($UserObject.DistinguishedName)"
    Set-AuditRule -AdObjectPath $AdObjectPath -WellKnownSidType WorldSid -Rights $Right -InheritanceFlags None -AuditFlags $AuditFlag -AttributeGUID $GUID
    
}

function Deploy-ComputerDeception {
<#
.SYNOPSIS
Deploys a decoy computer to log Security Event 4662 when a specific Right is used against it.

.DESCRIPTION
Sets up auditing for a specific right or attribute access against a decoy computer object in AD.
Must be run with domain admin privileges on a DC. Supports setting attacker-attractive properties and configuring auditing via SACLs.

.PARAMETER ComputerName
SamAccountName of the decoy computer.

.PARAMETER OperatingSystem
OperatingSystem attribute for the decoy computer.

.PARAMETER SPN
Set 'interesting' SPN for the decoy computer in the format servicename/host.

.PARAMETER PropertyFlag
A property such as TrustedForDelegation to make the decoy more interesting.

.PARAMETER Principal
Principal (user or group) to audit when it accesses the computer. Defaults to Everyone.

.PARAMETER Right
AD permission right to audit. Defaults to ReadProperty.

.PARAMETER GUID
Attribute GUID to target specific properties.

.PARAMETER AuditFlag
Success or Failure auditing. Defaults to Success.

.PARAMETER RemoveAuditing
Removes previously added audit ACEs if true.

.EXAMPLE
Deploy-ComputerDeception -ComputerName decoy01 -PropertyFlag TrustedForDelegation -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose
#>
    [CmdletBinding()] Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String] $ComputerName,

        [Parameter(Position = 1, Mandatory = $false)]
        [String] $OperatingSystem,

        [Parameter(Position = 2, Mandatory = $false)]
        [String] $SPN,

        [Parameter(Position = 3, Mandatory = $false)]
        [ValidateSet("AllowReversiblePasswordEncryption", "PasswordNeverExpires", "TrustedForDelegation")]
        [String] $PropertyFlag,

        [Parameter(Position = 4, Mandatory = $false)]
        [String] $Principal = "Everyone",

        [Parameter(Position = 5, Mandatory = $false)]
        [ValidateSet("GenericAll", "GenericRead", "GenericWrite", "ReadControl", "ReadProperty", "WriteDacl", "WriteOwner", "WriteProperty")]
        [String] $Right = "ReadProperty",

        [Parameter(Position = 6, Mandatory = $false)]
        [String] $GUID,

        [Parameter(Position = 7, Mandatory = $false)]
        [ValidateSet("Success", "Failure")]
        [String] $AuditFlag = "Success",

        [Parameter(Mandatory = $false)]
        [Bool] $RemoveAuditing = $false
    )

    if ($SPN) {
        Write-Verbose "Setting SPN '$SPN' on computer '$ComputerName'."
        Set-ADComputer -Identity $ComputerName -ServicePrincipalNames @{ Add = $SPN }
    }

    if ($OperatingSystem) {
        Write-Verbose "Setting OperatingSystem '$OperatingSystem' on computer '$ComputerName'."
        Set-ADComputer -Identity $ComputerName -OperatingSystem $OperatingSystem
    }

    if ($PropertyFlag) {
        Write-Verbose "Setting $PropertyFlag on computer '$ComputerName'."
        switch ($PropertyFlag) {
            "AllowReversiblePasswordEncryption" {
                Set-ADComputer -Identity $ComputerName -AllowReversiblePasswordEncryption $true
            }
            "PasswordNeverExpires" {
                Set-ADComputer -Identity $ComputerName -PasswordNeverExpires $true
            }
            "TrustedForDelegation" {
                Set-ADComputer -Identity $ComputerName -TrustedForDelegation $true
            }
        }
    }

    # Get the AD object path and call Set-AuditRule
    $ComputerObject = Get-ADComputer -Identity $ComputerName
    $AdObjectPath = "AD:$($ComputerObject.DistinguishedName)"

    Write-Verbose "Setting audit rule on $AdObjectPath for principal '$Principal' with right '$Right'."

    Set-AuditRule -AdObjectPath $AdObjectPath -WellKnownSidType WorldSid -Rights $Right -InheritanceFlags None -AuditFlags $AuditFlag -AttributeGUID $GUID -RemoveAuditing:$RemoveAuditing
}


function Deploy-GroupDeception
{
<#
.SYNOPSIS
Deploys the specific decoy group to log Security Event 4662 when a specific Right is used against it.

.DESCRIPTION
This function sets up auditing when a specified Right is used by a specifed principal against the decoy group object.

The function must be run on a DC with domain admin privileges. A decoy group can have members and the group can be
a member of other groups to make the decoy interesting for an attacker. 

When a right, say, ReadProperty is used to access the decoy group, a Security Event 4662 is logged. 

Note that Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> DS Access - Audit Directory Service Access
Group Policy needs to be configured to enable 4662 logging. 

.PARAMETER DecoyGroupName
SamAccountName of the decoy group.  

.PARAMETER AddMembers
Add list of Members to the decoy Group.

.PARAMETER AddToGroup
Make the decoy group a member of the specified group.

.PARAMETER Principal
The Principal (user or group) for which auditing is turned on when they use Rights defined by the Right or GUID paramter.

.PARAMETER Right
Thr Right for which auditing is turned on when used by the principal specified with the Principal parameter.
Default is ReadProperty right.

.PARAMETER GUID
GUID for the property for which auditing is turned on when Princpal uses Right on the property.

.PARAMETER AuditFlag
Turn on Auditing for Success or Failure. Default is Success.

.PARAMETER RemoveAuditing
Remove previously added Auditing ACE.

.EXAMPLE
PS C:\> Create-DecoyGroup -GroupName 'Forest Admins' -Verbose | Deploy-GroupDeception -AddMembers slaveuser -AddToGroup dnsadmins -Right ReadControl -Verbose 
Creates a decoy Group 'Forest Admins', adds slaveuser as a member and makes the group part of the dnsadmins group. 
A 4662 is logged whenever DACL or all the properties of the group are read.

.EXAMPLE
PS C:\> Create-DecoyGroup -GroupName "Forest Admins" -Verbose | Deploy-GroupDeception -AddMembers slaveuser -AddToGroup dnsadmins -GUID bc0ac240-79a9-11d0-9020-00c04fc2d4cf -Verbose
Creates a decoy Group 'Forest Admins',adds slaveuser as a member and makes the group part of the dnsadmins group.
A 4662 is logged whenever membership of the Forest Admins group is listed. 

.LINK
https://www.labofapenetrationtester.com/2018/10/deploy-deception.html
https://github.com/samratashok/Deploy-Deception
#>
    [CmdletBinding()] Param(
        
        [Parameter(Position = 0, Mandatory = $False,ValueFromPipeline = $True)]
        [String]
        $DecoyGroupName,
     
        [Parameter(Position = 1, Mandatory = $False)]        
        [String[]]
        $AddMembers,

        [Parameter(Position = 2, Mandatory = $False)]
        [String]
        $AddToGroup,

        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        $Principal = "Everyone",

        [Parameter(Position = 4, Mandatory = $False)]
        [String]
        [ValidateSet ("GenericAll","GenericRead","GenericWrite","ReadControl","ReadProperty","WriteDacl","WriteOwner","WriteProperty")]
        $Right = "ReadProperty",

        [Parameter(Position = 5, Mandatory = $False)]
        [String]
        $GUID,

        [Parameter(Position = 6, Mandatory = $False)]
        [String[]]
        [ValidateSet ("Success","Failure")]
        $AuditFlag = "Success",

        [Parameter(Mandatory = $False)]
        [Bool]
        $RemoveAuditing = $False
    )

    if ($AddMembers)
    {
        Write-Verbose "Adding members $AddMembers to $DecoyGroupName."
        Add-ADGroupMember -Identity $DecoyGroupName -Members $AddMembers
    }
    if($AddToGroup)
    {
        Write-Verbose "Adding $DecoyGroupName to $AddToGroup."
        Add-ADGroupMember -Identity $AddToGroup -Members $DecoyGroupName
    }

    $GroupObject = Get-ADGroup -Identity $DecoyGroupName
    $AdObjectPath = "AD:$($GroupObject.DistinguishedName)"

    Write-Verbose "Setting audit rule on $AdObjectPath for principal '$Principal' with right '$Right'."

    Set-AuditRule -AdObjectPath $AdObjectPath -WellKnownSidType WorldSid -Rights $Right -InheritanceFlags None -AuditFlags $AuditFlag -AttributeGUID $GUID -RemoveAuditing:$RemoveAuditing 
}

function Deploy-OUDeception {
<#
.SYNOPSIS
Deploys a decoy OU and applies auditing to generate Security Event 4662 on access.

.PARAMETER OUDistinguishedName
The full DN of the OU (e.g., "OU=FakeOU,DC=corp,DC=example,DC=com").

.PARAMETER WellKnownSidType
The SID type to audit (e.g., WorldSid, AuthenticatedUserSid).

.PARAMETER Right
The AD right to audit (default: ReadProperty).

.PARAMETER AuditFlag
Whether to audit Success, Failure, or both (default: Success).

.PARAMETER InheritanceFlags
Inheritance setting for the rule (default: None).

.PARAMETER AttributeGUID
GUID of the attribute to audit (optional).

.PARAMETER RemoveAuditing
Remove instead of add auditing.
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$OUDistinguishedName,

        [Parameter(Mandatory = $false)]
        [ValidateSet("WorldSid", "AuthenticatedUserSid", "AccountDomainUsersSid", "AccountDomainAdminsSid", "EveryoneSid")]
        [string]$WellKnownSidType = "WorldSid",

        [Parameter()]
        [ValidateSet("GenericAll", "GenericRead", "GenericWrite", "ReadControl", "ReadProperty", "WriteDacl", "WriteOwner", "WriteProperty")]
        [string]$Right = "ReadProperty",

        [Parameter()]
        [ValidateSet("Success", "Failure")]
        [string]$AuditFlag = "Success",

        [Parameter()]
        [ValidateSet("None", "All", "Descendents", "SelfAndChildren")]
        [string]$InheritanceFlags = "None",

        [Parameter()]
        [string]$AttributeGUID,

        [Parameter()]
        [bool]$RemoveAuditing = $false
    )

    try {
        Write-Verbose "Deploying decoy OU auditing for $OUDistinguishedName"

        Set-AuditRule -AdObjectPath "AD:\$OUDistinguishedName" `
                      -WellKnownSidType $WellKnownSidType `
                      -Rights $Right `
                      -InheritanceFlags $InheritanceFlags `
                      -AuditFlags $AuditFlag `
                      -AttributeGUID $AttributeGUID `
                      -RemoveAuditing:$RemoveAuditing

        Write-Output "Audit rule successfully applied to $OUDistinguishedName"
    }
    catch {
        Write-Error "Failed to apply audit rule to OU: $_"
    }
}


function Deploy-GPODeception {
    <#
    .SYNOPSIS
    Applies auditing to a GPO object to detect access attempts.

    .DESCRIPTION
    Sets SACL entries on the GPO to log security events when a specified user or group accesses or modifies the GPO.

    .PARAMETER GpoName
    Name of the GPO to audit.

    .PARAMETER Principal
    User or group to monitor (default: Everyone).

    .PARAMETER Right
    The AD right to audit (default: ReadProperty).

    .PARAMETER AuditFlag
    Success or Failure auditing (default: Success).

    .PARAMETER RemoveAuditing
    Remove audit rules instead of adding them.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$GpoName,

        [Parameter()]
        [string]$Principal = "Everyone",

        [Parameter()]
        [ValidateSet("GenericAll","GenericRead","GenericWrite","ReadControl","ReadProperty","WriteDacl","WriteOwner","WriteProperty")]
        [string]$Right = "ReadProperty",

        [Parameter()]
        [ValidateSet("Success", "Failure")]
        [string]$AuditFlag = "Success",

        [Parameter()]
        [bool]$RemoveAuditing = $false
    )

    $gpo = Get-GPO -Name $GpoName -ErrorAction Stop
    $gpoDN = "CN={$($gpo.Id)},CN=Policies,CN=System,$((Get-ADDomain).DistinguishedName)"

    Write-Verbose "Configuring auditing on GPO: $GpoName ($gpoDN)"

    Set-AuditRule -AdObjectPath "AD:\$gpoDN" `
                  -WellKnownSidType WorldSid `
                  -Rights $Right `
                  -AuditFlags $AuditFlag `
                  -InheritanceFlags None `
                  -RemoveAuditing:$RemoveAuditing
}

function Save-HoneyAudit {
    <#
    .SYNOPSIS
    Saves AD objects based on Distinguished Name to a file for tracking purposes

    .DESCRIPTION
    Takes DNs of AD objects and adds their object GUID to a txt file to be used by other functions and track honeypots 

    .PARAMETER DN
    Distinguished Name of object to be added
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$DN
    )

    $file = ".\honeyaudit.txt"

    try {
        $obj = Get-ADObject -Identity $DN -Properties ObjectGUID
        $guid = $obj.ObjectGUID.Guid
        $entry = "$guid"

        if (!(Test-Path $file)) {
            Write-Host "Creating new audit tracking file..."
            Set-Content -Path $file -Value $entry
        } else {
            Add-Content -Path $file -Value $entry
        }

        Write-Host "Saved audit tracking for: $DN"
    }
    catch {
        Write-Error "Failed to resolve DN to object: $_"
    }
}

function Pull-HoneyAudit {
    <#
    .SYNOPSIS
    Gives a terminal output of recent audit events for honeypots saved for tracking

    .DESCRIPTION
    Reads the tracking file for GUIDs and checks event logs for recent auditing events. Prints these recent events into the terminal for review. 
    #>
    $file = ".\honeyaudit.txt"

    if (!(Test-Path $file)) {
        Write-Warning "Audit tracking file not found."
        return
    }

    $guids = Get-Content $file

    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4662} -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to read Security log: $_"
        return
    }

    if (-not $events) {
        Write-Warning "No 4662 events found in Security log."
        return
    }

    foreach ($guid in $guids) {
        try {
            $obj = Get-ADObject -Filter {ObjectGUID -eq $guid} -Properties DistinguishedName
            $dn = $obj.DistinguishedName
        }
        catch {
            Write-Warning "Could not resolve GUID $guid to a DN. Skipping..."
            continue
        }

        $matched = @()

        foreach ($e in $events) {
            if ($e.Message -like "*$guid*") {
                $matched += $e
            }
        }

        Write-Host "`n=== Audit Results for: $dn ==="
        if ($matched.Count -eq 0) {
            Write-Host "  No events found."
        }
        else {
            Write-Host "  Found $($matched.Count) events:"
            foreach ($evt in $matched) {
                Write-Host "    [$($evt.TimeCreated)] - Event ID $($evt.Id)"
                $summary = $evt.Message.Split("`n") | Where-Object { $_ -match 'Accesses|Object Type|Object Name' }
                $summary | ForEach-Object { Write-Host "      $_" }
            }
        }
    }
}




