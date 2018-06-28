param([string]$SqlServerInstance,
      [string]$SqlAdminUser,
      [string]$SqlAdminPassword,
      [string]$SqlIpPbxDatabaseName,
      [string]$SqlIpPbxUser,
      [string]$SqlIpPbxPassword,
      [string]$IpPbxAdminUser,
      [string]$IpPbxAdminPassword,
      [string]$VerboseMode)

###################################################################      
# FUNCTIONS
###################################################################

function Test-DatabaseConnection
{
    param([parameter(Mandatory=$true)][string]$ServerInstance,
          [parameter(Mandatory=$true)][string]$AdminUser,
          [parameter(Mandatory=$true)][string]$AdminPassword)

    $retries = 5
    $connected = $false

    do
    {
        Write-Host "Checking database connection (remaining attempts: $($retries))"
    
        $sqlConnection = New-Object System.Data.SqlClient.SqlConnection
        $sqlConnection.ConnectionString = "Server=$($ServerInstance);Database=master;Integrated Security=false;User ID=$($AdminUser);Password=$($AdminPassword);Connection Timeout=5;"

        try
        {
            $sqlConnection.Open()
            $connected = $true
            $sqlConnection.Close()
        }
        catch
        {
            if ($_ -and $_.Exception -and $_.Exception.InnerException)
            {
                Write-Warning $_.Exception.InnerException.Message
            }
            else
            {
                $_
            }

            Write-Host "Next try in 10 seconds..."
            Start-Sleep -Seconds 10            
        }

        $retries--
    }
    while ($retries -gt 0 -and -not $connected)

    if (!($connected))
    { 
        Write-Error "Database connection could not be established" -ErrorAction Stop
    }
    else
    {
        Write-Host "Database connection tested successfully"
    }
}

function Update-UnattendedXml
{
    param([parameter(Mandatory=$true)][string]$ConfigFilePath,
          [parameter(Mandatory=$true)][string]$SqlServerInstance,
          [parameter(Mandatory=$true)][string]$SqlAdminUser,
          [parameter(Mandatory=$true)][string]$SqlAdminPassword,
          [parameter(Mandatory=$true)][string]$SqlIpPbxDatabaseName,
          [parameter(Mandatory=$true)][string]$SqlIpPbxUser,
          [parameter(Mandatory=$true)][string]$SqlIpPbxPassword)
    
    Write-Host "Preparing the Unattended.xml file update..."
    
    # Create xml document object and load unattended.xml
    $xmlData = New-Object System.Xml.XmlDocument
    $xmlData.PreserveWhitespace = $true
    $xmlData.Load($ConfigFilePath)
    
    # Create a namespace manager object for XPaths to work correctly
    $nsmgr = New-Object "System.Xml.XmlNamespaceManager" $xmlData.NameTable
    $nsmgr.AddNamespace("c", "http://www.lanphone.de/schemas/2008/IpPbxConfiguration")
    $nsmgr.AddNamespace("l", "http://www.lanphone.de/schemas/2008/IpPbxConfiguration/LicenseTask")

    # Create collection with patch information
    $parameterUpdateList = @(
        @{XPath="//c:Parameter[@Name='SQLServerInstance']";Value=$SqlServerInstance},
        @{XPath="//c:Parameter[@Name='SQLAdminLoginMode']";Value="SQL"},
        @{XPath="//c:Parameter[@Name='SQLAdminLoginUser']";Value=$SqlAdminUser},
        @{XPath="//c:Parameter[@Name='SQLAdminLoginPassword']";Value=$SqlAdminPassword},
        @{XPath="//c:Parameter[@Name='SQLIpPbxLoginUser']";Value=$SqlIpPbxUser},
        @{XPath="//c:Parameter[@Name='SQLIpPbxLoginPassword']";Value=$SqlIpPbxPassword},
        @{XPath="//c:Parameter[@Name='SQLBackupDatabase']";Value="false"},
        @{XPath="//c:Parameter[@Name='SQLIpPbxDatabaseName']";Value=$SqlIpPbxDatabaseName},
        @{XPath="//c:Parameter[@Name='SQLIpPbxUseFileSystem']";Value="false"},
        @{XPath="//c:Parameter[@Name='SMTPServerCheck']";Value="false"},
        @{XPath="//c:Parameter[@Name='GenerateNewRootAndServerCertificates']";Value="true"},
        @{XPath="//l:LicenseMode";Value="Evaluation"}
    )

    # Do the update
    Write-Host "Updating parameter values..."

    $xmlData.IpPbxConfiguration.mode = "manual"

    $parameterUpdateList | ForEach-Object {

        $node = $xmlData.SelectSingleNode($_.XPath, $nsmgr)
        if (!$node)
        {
            Write-Warning "Failure -> '$($_.XPath)'"
            return
        }

        $node.innertext = $_.Value
        Write-Verbose "Success -> '$($_.XPath)'"
    }

    Write-Verbose "Saving changes..."
    $xmlData.Save($ConfigFilePath)
    
    Write-Host "Unattended.xml updated successfully"
}

function Update-LicenseLocation
{
     Write-Host "Updating license.dat file location..."

    $serverOptionsRegPath       = "HKLM:\SOFTWARE\WOW6432Node\Swyx\IpPbxSrv\CurrentVersion\Options"
    $licenseLocationRegKeyName  = "LicensePath"
    $licenseLocationRegKeyValue = "C:\ProgramData\Swyx\Licenses\"
    
    $regKey = Get-ItemProperty -Path $serverOptionsRegPath `
                               -Name $licenseLocationRegKeyName `
                               -ErrorAction SilentlyContinue

    # Check if the license location registry key exists
    if (!$regKey)
    {    
    
        Write-Verbose "Creating license location registry key -> '$($serverOptionsRegPath)\$($licenseLocationRegKeyName)'"
        New-ItemProperty -Path $serverOptionsRegPath `
                         -Name $licenseLocationRegKeyName `
                         -Value $licenseLocationRegKeyValue `
                         -PropertyType String `
                         -Force | Out-Null    
    }
    else
    {
        Write-Verbose "License location registry key found"
        Write-Verbose "Path:  '$($serverOptionsRegPath)\$($licenseLocationRegKeyName)'"
        Write-Verbose "Value: '$($regKey.LicensePath)'"
    
        # Ensure that the location is correct
        if ($regKey.LicensePath -ne $licenseLocationRegKeyValue)
        {        
            Set-ItemProperty -Path $serverOptionsRegPath `
                             -Name $licenseLocationRegKeyName `
                             -Value $licenseLocationRegKeyValue `
                             -Force | Out-Null
        
            Write-Verbose "License location registry key updated -> '$($licenseLocationRegKeyValue)'"
        }
    }
}

function Do-KeepAlive
{    
    Write-Verbose "Keeping container alive..."

    $lastCheck = (Get-Date).AddSeconds(-22)
    
    while ($true) {
    
        if ($VerbosePreference -eq "continue")
        {
            $entries = @(Get-EventLog -LogName SwyxWare -Source "*" -After $lastCheck -ErrorAction SilentlyContinue)
            $entries | Select-Object TimeGenerated, EntryType, Source, Message
            $lastCheck = Get-Date
        }

        Start-Sleep -Seconds 20
    }
    
    exit
}

###################################################################      
# MAIN
###################################################################

# Initialization
$scriptFolder = (Split-Path $MyInvocation.MyCommand.Path -Parent)

# Check if verbose mode was requested
if ($VerboseMode.ToLowerInvariant() -eq "true")
{
    $VerbosePreference = "continue" 
}

# Set Error Preference (for debugging use 'SilentlyContinue')
$ErrorActionPreference = 'Stop';

# Check if container is already configured
if (Test-Path "C:\AlreadyConfigured.dat")
{
    Write-Host "Container is already configured. Let’s keep it alive..."
    Do-KeepAlive
}
   
# Validate required SQL Server parameters
if (!$SqlServerInstance -or `
     $SqlServerInstance -like "%*%" -or `
    !$SqlAdminPassword -or `
     $SqlAdminPassword -like "%*%")
{
    Write-Warning "The value for the parameter 'SqlServerInstance' and/or 'SqlAdminPassword' is missing. Container cannot be started."
    
    if ($VerbosePreference -eq "continue")
    {
        Do-KeepAlive
    }
    
    exit
}

# Check parameters and set default values if required
if (!$SqlAdminUser -or `
     $SqlAdminUser -like "%*%")
{
    $SqlAdminUser = "sa"
}

if (!$SqlIpPbxDatabaseName -or `
     $SqlIpPbxDatabaseName -like "%*%")
{
    $SqlIpPbxDatabaseName = "ippbx"
}

if (!$SqlIpPbxUser -or `
     $SqlIpPbxUser -like "%*%")
{
    $SqlIpPbxUser = "ippbx_user"
}

$IsSqlIpPbxDefaultPassword = $false
if (!$SqlIpPbxPassword -or `
     $SqlIpPbxPassword -like "%*%")
{
    $IsSqlIpPbxDefaultPassword = $true
    $SqlIpPbxPassword = "C0mplicated_Passw0rd"
}

if ($IpPbxAdminUser -like "%*%")
{
    $IpPbxAdminUser = ""
}

if ($IpPbxAdminPassword -like "%*%")
{
    $IpPbxAdminPassword = ""
}
               
# Define vars for IpPbx configuration
$ipPbxInstallPath      = "C:\Program Files (x86)\SwyxWare"
$ipPbxConfigFilePath   = Join-Path $ipPbxInstallPath "IpPbxConfig.exe"
$ipPbxConfigArgList    = @("/c:Unattended.xml")
$ipPbxUnattendedArgs   = "/cp ContainerInstallation=true"
$unattendedXmlFilePath = Join-Path $ipPbxInstallPath "Unattended.xml"

if ($IpPbxAdminUser)
{       
    $ipPbxUnattendedArgs += ";ContainerAdminUserName=$($IpPbxAdminUser)"
}

if ($IpPbxAdminPassword)
{
    $ipPbxUnattendedArgs += ";ContainerAdminUserPassword=$($IpPbxAdminPassword)"
}       

$ipPbxConfigArgList += $ipPbxUnattendedArgs

if ($VerbosePreference -eq "continue")
{
    $ipPbxConfigArgList += "/verbose"
}

# Useful debug output
Write-Verbose "SqlServerInstance:     '$($SqlServerInstance)'"
Write-Verbose "SqlAdminUser:          '$($SqlAdminUser)'"
Write-Verbose "SqlAdminPassword:      '<hidden>'"
Write-Verbose "SqlIpPbxDatabaseName:  '$($SqlIpPbxDatabaseName)'"
Write-Verbose "SqlIpPbxUser:          '$($SqlIpPbxUser)'"

if ($IsSqlIpPbxDefaultPassword)
{    
    Write-Verbose "SqlIpPbxPassword:      '<default>'"
}
else
{
    Write-Verbose "SqlIpPbxPassword:      '<hidden>'"
}

Write-Verbose "IpPbxAdminUser:        '$($IpPbxAdminUser)'"

if ($IpPbxAdminPassword)
{
    Write-Verbose "IpPbxAdminPassword:    '<hidden>'"
}
else
{
    Write-Verbose "IpPbxAdminPassword:    '<default>'"
}

Write-Verbose "IpPbxConfigFilePath:   '$($ipPbxConfigFilePath)'"
Write-Verbose "IpPbxConfigArgList:    '$($ipPbxConfigArgList)'"
Write-Verbose "UnattendedXmlFilePath: '$($unattendedXmlFilePath)'"

# Validate installation 
if (!(Test-Path $ipPbxConfigFilePath))
{
    Write-Error "The configuration executable could not be found. Aborting process..." -ErrorAction Stop
}

if (!(Test-Path $unattendedXmlFilePath))
{
    Write-Error "The unattended.xml could not be found. Aborting process..." -ErrorAction Stop
}

# Check if SQL container is available
Test-DatabaseConnection -ServerInstance $SqlServerInstance `
                        -AdminUser $SqlAdminUser `
                        -AdminPassword $SqlAdminPassword

# Update SQL parameters inside the Unattended.xml
Update-UnattendedXml -ConfigFilePath $unattendedXmlFilePath `
                     -SqlServerInstance $SqlServerInstance `
                     -SqlAdminUser $SqlAdminUser `
                     -SqlAdminPassword $SqlAdminPassword `
                     -SqlIpPbxDatabaseName $SqlIpPbxDatabaseName `
                     -SqlIpPbxUser $SqlIpPbxUser `
                     -SqlIpPbxPassword $SqlIpPbxPassword

# Change the license.dat location via registry key
# The directory is created by IpPbx server during the service start
Update-LicenseLocation

# Configuration
Write-Host "Configuring IpPbx Server..."
$process = Start-Process -FilePath $ipPbxConfigFilePath `
                         -ArgumentList $ipPbxConfigArgList `
                         -WorkingDirectory $ipPbxInstallPath `
                         -Wait `
                         -NoNewWindow `
                         -ErrorAction Stop `
                         -PassThru
                         
if ($process.ExitCode -eq 0)
{
    # Create a dummy file to remember that this machine is already configured 
    Write-Verbose "Creating 'AlreadyConfigured.dat'..."
    New-Item -Path C:\ -Name AlreadyConfigured.dat -Value "DO NOT DELETE THIS FILE" -ItemType File | Out-Null              
                  
    # Status Output
    Write-Host "Configuration completed"
    
    # Keep container alive
    Do-KeepAlive
}
elseif ($VerbosePreference -eq "continue")
{
    Write-Verbose "Configuration failed :-("
    Write-Verbose "Keeping container alive for debugging purposes..."

    # Keep container alive
    Do-KeepAlive
}
