<#
.SYNOPSIS
    Deploys SwyxWare + SQLExpress as docker container
.PARAMETER ContainerSubnet
    Subnet of the container (CIDR) notation, e.g. 192.168.100.0/28. This has to be the same or smaller than the host subnet
.PARAMETER ContainerDefaultGateway
    Default Gateway IP address to be used for the container. This should be identical to the host's default gateway
.PARAMETER SqlServerInstanceName
    Name of an existing SQLServer instance to be used. Specify sysadmin credentials via parameter SqlAdminCredentials for admin access to
    that instance. Leave empty create a SqlExpress container
.PARAMETER SQLContainerIPAddress
    IP address to assign to the SQLExpress container. Has to be in the ContainerSubnet
.PARAMETER IpPBxContainerIPAddress
    IP address to assign to the SwyxWare container. Has to be in the ContainerSubnet
.PARAMETER SqlAdminCredentials
    SQL Administrator username and password. Needs to be an existing SQL admin login if you use a separate, existing SQL server intance. 
    Specify username 'sa' and a complex password when a SQLExpress container is to be deployed
.PARAMETER IpPbxAdminCredentials
    SwyxWare Administrator username and password. A SwyxWare user with system administrator rights will be created if
    a new swyxware database is created during deployment.
.PARAMETER DockerHubCredentials
    hub.docker.com credential to access a private repository. 
.PARAMETER LogfilePath
    Logfile path and filename. Uses console logging if paramter is not set     
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [string]$ContainerSubnet,
    [string]$ContainerDefaultGateway,
    [string]$SQLServerInstanceName,
    [string]$SQLContainerIPAddress,
    [string]$IpPbxContainerIPAddress,
    [PSCredential]$SqlAdminCredentials,
    [PSCredential]$IpPbxAdminCredentials,
    [PSCredential]$DockerHubCredentials,
    [string]$LogfilePath
    )


# Get script path 
$scriptFolder = (Split-Path $MyInvocation.MyCommand.Path -Parent)

# some defaults
$ContainerNetworkName = "ippbxnet"
$SQLContainerName     = "ippbxdb"
$IpPbxContainerName   = "ippbx01"
$SQLAdminName         = "sa"
$SQLAdminPassword     = "" # will be prompted or set from given SqlCredentials

$SqlExpressContainerImageName        = "microsoft/mssql-server-windows-express:latest"
$WindowsServerCoreContainerImageName = "microsoft/windowsservercore"
$SwyxWareContainerImageName          = "swyx/swyxware-cpe:11.00"
$HostDataFolder                      = join-path ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData)) "Swyx"
$ContainerDataFolder                 = $HostDataFolder

$RedirectOutputFile = join-path $Env:TEMP docker-out.log

#Function to Test the DatabaseConnection (Also used in the SwyxWare Docker container)
function Test-DatabaseConnection
{
    param([parameter(Mandatory=$true)][string]$ServerInstance,
          [parameter(Mandatory=$true)][string]$AdminUser,
          [parameter(Mandatory=$true)][SecureString]$AdminPassword)

    $retries = 5
    $connected = $false

    do
    {
        Add-LogMessage -level Verbose -Message "Checking database connection (remaining attempts: $($retries))"
    
        $sqlConnection = New-Object System.Data.SqlClient.SqlConnection
        $PlainTextSQlPassword = (New-Object PSCredential -ArgumentList "User",$AdminPassword).GetNetworkCredential().Password
        $sqlConnection.ConnectionString = "Server=$($ServerInstance);Database=master;Integrated Security=false;User ID=$($AdminUser);Password=$($PlainTextSQlPassword);Connection Timeout=5;"
        $PlainTextSQlPassword = $null

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
                Add-LogMessage -Level Warn -Message $_.Exception.InnerException.Message
            }
            else
            {
                $_
            }

            Add-LogMessage -Level Verbose -Message "Next try in 10 seconds..."
            Start-Sleep -Seconds 10            
        }

        $retries--
    }
    while ($retries -gt 0 -and -not $connected)

    if (!($connected))
    { 
        Add-LogMessage -Level Error -Message "Database connection could not be established please check your Parameters"
        return $false
    }
    else
    {
        Add-LogMessage -Level Info -Message "Database connection tested successfully"
        return $true
    }
}

function Get-DockerImage
{
    param($ImageName)

    Add-LogMessage -Level Info -Message "Pulling $ImageName Container image."
    
    docker pull $ImageName

    if ($LASTEXITCODE -ne 0)
    {
        Add-LogMessage -Level Error -ThrowException -Message  "An  error occured during 'docker pull'"
    }     
}


if (!((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)))
{
    Add-LogMessage -Level Error -ThrowException -Message  "This script needs to be run elevated, i.e. with local administrator privileges."
}


# Initialise logging
if (!$LogfilePath) {
    $logDirectoryPath  = Join-Path ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData)) "Swyx\Traces"
    $logFilePath       = Join-Path $logDirectoryPath "Start-IpPbxDockerDeployment_$((Get-Date).ToString("yyyyMMdd_hhmmss")).log"
}

# Create log directory if it does not exist
if (!(Test-Path -Path $logDirectoryPath))
{
    New-Item -Path $logDirectoryPath -ItemType Directory -ErrorAction Stop | Out-Null    
}

. (join-path $scriptFolder "Resources\Init-Logging.ps1")

$logThreshold = [log4net.Core.Level]::Info
if ($VerbosePreference -eq "Continue") {
    $logThreshold = [log4net.Core.Level]::Verbose
}

Init-Logging -targetpath $logFilePath -threshold $logthreshold -append:$false

# Debug output
Add-LogMessage -Level Verbose -Message "$($MyInvocation.MyCommand.Name) script started at '$(Get-Date)'"
Add-LogMessage -Level Verbose -Message "ScriptDirectory:     '$ScriptFolder)'"
Add-LogMessage -Level Verbose -Message "LogFilePath:         '$logFilePath'"
Add-LogMessage -Level Verbose -Message "ContainerNetworkName '$ContainerNetworkName'"
Add-LogMessage -Level Verbose -Message "SqlContainerName:    '$SQLContainerName'"
Add-LogMessage -Level Verbose -Message "IpPbxContainerName:  '$IpPbxContainerName'"
Add-LogMessage -Level Verbose -Message "SQLAdminName:        '$SQLAdminName'"



#Checking if Docker module is installed.

if ($PSCmdLet.ShouldProcess("Container Support","Install Windows Feature"))
{
    if (Get-PackageProvider -Name DockerMsftProvider -ErrorAction SilentlyContinue) {
       Add-LogMessage -Level Verbose -Message "Package provider 'DockerMsftProvider' is already installed"
    } 
    else 
    {
        Add-LogMessage -Level Info -Message "Package provider 'DockerMsftProvider' not found. Installing..."
        Add-LogMessage -Level Info -Message "You might get several confirmation prompts from Windows during installation. Answer 'y' to proceed"
        Install-Module -Name DockerMsftProvider -Repository PSGallery -Force -ErrorAction Stop
        Add-LogMessage -Level Info -Message "Module 'DockerMsftProvider' fetched successfully."
        $RestartRequired = $true
    }

    if (Get-Package -Name Docker -ProviderName DockerMsftProvider -ErrorAction SilentlyContinue) {
        Add-LogMessage -Level Verbose -Message "Package 'docker' is already installed."
    } 
    else 
    {
        Add-LogMessage -Level Info -Message "Package 'docker' not found. Installing..."
        Add-LogMessage -Level Info -Message "You might get several confirmation prompts from Windows during installation. Answer 'y' to proceed"
        Install-Package -Name Docker -ProviderName DockerMsftProvider -Force -ErrorAction Stop | out-null
        Add-LogMessage -Level Info -Message "Package 'docker' installed successfully."
        $RestartRequired = $true
    }
}


if($RestartRequired)
{
    Add-LogMessage -Level Info -Message "A system restart is required to enable Windows Container support."
    if ($PSCmdLet.ShouldContinue("Restart computer to enable Windows Container support.", "Restart required"))
    {
        Restart-Computer -force
        return
    }
    else
    {
        Add-LogMessage -Level Warning -Message "Script cannot continue before you restart the computer."
        return
    }

    start-service -Name Docker
}


# Create Docker Network
$NetworkID = docker network ls --filter "name=$ContainerNetworkName" --no-trunc --quiet
if ($NetworkID)
{
    Add-LogMessage -Level Verbose -Message "Container network $ContainerNetworkName already exists."
    $ExistingNetwork = docker network inspect $ContainerNetworkName
    Add-LogMessage -Level Verbose -Message (ConvertFrom-Json -InputObject ([string]$ExistingNetwork) | ConvertTo-Json)
}
else
{
    if(!($ContainerSubnet))
    {
        $OwnIPAddresses = @(Get-NetIPAddress -AddressFamily IPv4 -Type Unicast -AddressState Preferred | Where-Object { $_.SuffixOrigin -ne "WellKnown" -and ($_.InterfaceAlias -notmatch "vEthernet" -or $_.InterfaceAlias -match "vEthernet \(HNSTransparent") })
        $OWnIPAddresses | foreach-object { Add-LogMessage -Level Verbose -Message "Found own IP: $($_.IPAddress)" }
        if ($OwnIPAddresses.Count -eq 1) {
            $DefaultContainerSubnet = $OwnIPAddresses[0].IPAddress + "/$($OwnIPAddresses[0].PrefixLength)"
        }
        $ContainerSubnet = Read-Host "Enter Container network subnet [$DefaultContainerSubnet]"
        if (!$ContainerSubnet) { $ContainerSubnet = $DefaultContainerSubnet }
        Add-LogMessage -Level Verbose -Message "ContainerNetwork Subnet $ContainerSubnet"
    }

    if(!($ContainerDefaultGateway))
    {
        $OwnIPConfiguration = @(Get-NetIPConfiguration  | Where-Object { $_.InterfaceAlias -notmatch "vEthernet" } )
        if ($OwnIPConfiguration.Count -eq 1) {
            $DefaultContainerDefaultGateway = $OwnIPConfiguration[0].IPV4DefaultGateway.NextHop
        }
        $ContainerDefaultGateway = Read-Host "Container network default gateway ip address [$DefaultContainerDefaultGateway]"
        if (!$ContainerDefaultGateway) { $ContainerDefaultGateway = $DefaultContainerDefaultGateway }
        Add-LogMessage -Level Verbose -Message "Enter ContainerNetwork Default gatewqy $ContainerDefaultGateway"
    }

    if ($PSCmdlet.ShouldProcess("Transparent Containernetwork '$ContainerNetworkname'",'Create')) {
        $dockernetworkResult = docker network create --driver=transparent --ipv6=false --subnet=$ContainerSubnet --gateway=$ContainerDefaultGateway $ContainerNetworkName

        if ($dockernetworkResult.contains("Error") )
        {
            Add-LogMessage -Level Error -ThrowException -Message "Network could not be created. Please check your parameters"
        }
        else
        {
            # if network has just been created, it make take a while until Window regain connectivity
            $Retries = 5
            while ($retries-- -and -not (Get-NetIPConfiguration | Where-Object { $_.IPv4Address.ipAddress -eq "10.211.55.21" })) {
                    start-sleep -Seconds 5
                }
            Add-LogMessage -Level Info -Message "Docker Network '$ContainerNetworkName' has been created successfully."
        }
    }
}

# pull windows server core base image
Get-DockerImage -ImageName $WindowsServerCoreContainerImageName

#SQL Server Configuration

$SQLContainerID = docker container ls --filter "name=ippbxdb" --quiet
if ($SQLContainerID) {
    Add-LogMessage -Level Info -Message "SQL container '$SqlContainerName' already running. Will use it."
    $ExistingSqlContainer = docker container inspect $SqlContainerName
    Add-LogMessage -Level Verbose -Message (ConvertFrom-Json -InputObject ([string]$ExistingSqlContainer) | ConvertTo-Json)
    if (!$SqlAdminCredentials) {
        Add-LogMessage -level Error -ThrowException -Message "SQL Admin credentials not specified. Cannot continue."
    }
    $SQLServerInstance = "$SQlContainerName\SqlExpress" 
    $SQLAdminPassword = $SqlAdminCredentials.Password
}
else
{
    if(!$SQLServerInstance)
    {
        $SQLServerInstance = Read-Host 'Enter the SQL Server instance to use. Leave empty to run a SQLExpress container []'
       
    }

    Add-LogMessage -Level Verbose -Message "Using SqlServerInstance '$SQLServerInstance'"

    if (!$SqlAdminCredentials) {
        $DefaultSqlAdminName = $SQLAdminName
        $SQLAdminName = Read-Host "Please enter your SQL Server Admin Username '[$DefaultSqlAdminName]'"
        if (!$SQLAdminName) { $SQLAdminName = $DefaultSqlAdminName }
        $SQLAdminPassword = Read-Host -assecurestring 'Enter the password of the SQL '$SqlAdminName' user'
    }
    else
    {
        $SQLAdminName = $SqlAdminCredentials.UserName
        $SQLAdminPassword = $SqlAdminCredentials.Password
    }
    Add-LogMessage -Level Verbose -Message "Using SQL admin '$SqlAdminName'."

    #No SQL Server available. Create one via Docker Container
    if(!$SQLServerInstance)
    {
        Add-LogMessage -Level Info -Message "Pulling SQL Server Container image."
    	Get-DockerImage -ImageName $SqlExpressContainerImageName 
    
        if(!$SQLContainerIP)
        {
            $SQLContainerIP = Read-Host 'Enter the static IP address for the SQL Server container'
        }

        #TODO (Nice to have): Validation of IP address BEFORE container launch
        
        docker container rm --force $SQlContainerName  

        $PlainTextSQlPassword = (new-object "PSCredential" -ArgumentList "user",$SQLAdminPassword).GetNetworkCredential().Password
        docker run -d --network=$ContainerNetworkName --ip $SQLContainerIP --hostname $SQlContainerName --name $SQlContainerName -e SA_PASSWORD=$PlainTextSQlPassword -e ACCEPT_EULA=Y $SqlExpressContainerImageName  | Tee-Object -LiteralPath $RedirectOutputFile 
        $DockerRunResult = $LASTEXITCODE
        $PlainTextSQlPassword = $null

        if ($DockerRunResult -ne 0)
        {   
            Add-LogFromFile -Level Error -FilePath $RedirectOutputFile 
            remove-item -LiteralPath $RedirectOutputFile -Force
            throw "SQL Server container could not be started. Docker run command stopped with exit code '$($process.ExitCode)'."
        }
        else {
            Add-LogMessage -Level Info -Message "SQL Container started"
            Add-LogFromFile -Level Info -FilePath $RedirectOutputFile 
        }
        remove-item -LiteralPath $RedirectOutputFile -Force | out-null

        $SQLServerInstance = "$SQlContainerName\SqlExpress"            
    }
}

#Testing Database Connection
if (! (Test-DatabaseConnection -ServerInstance $SqlServerInstance -AdminUser $SQLAdminName -AdminPassword $SqlAdminPassword)) {
    Add-LogMessage -Level Error -ThrowException -Message "Cannot connect to SQL server."
}


#SwyxWare Docker Container

#If the SwyxWare Docker Image is not public, log in to Docker Hub
if($DockerHubCredentials)
{
    #Login to Docker Hub
    $loggedin = $false
    while(!$loggedin)
    {
        Add-LogMessage -Level Info -Message "Logging on to Docker Hub..."
        $PlainTextPassword = $DockerHubCredentials.GetNetworkCredential().Password
        docker login -u $DockerHubCredentials.UserName -p $PlainTextPassword   	
        if ($LASTEXITCODE -ne 0)
        {
    	    throw "Login failed"
        }
        else
        {
    	    Add-LogMessage -Level Info -Message "Login succeeded"
            $loggedin = $true
        }
    }
}


$ExistingIpPbxContainer = docker container ls -a --filter "name=$IpPbxContainerName" --quiet
if ($ExistingIpPbxContainer -and $PSCmdLet.ShouldContinue("Stop and remove existing container $IpPbxContainerName","Container exists")) { 

    docker stop $ExistingIpPbxContainer
    docker rm $ExistingIpPbxContainer
}
elseif ($ExistingIpPbxContainer)
{
    Add-LogMessage -Level Warn -Message "Container $IpPbxContainerName already running. Cannot continue."
    return
}

#Pull SwyxWare Docker Image
Get-DockerImage -ImageName $SwyxWareContainerImageName

if(!$IpPbxContainerIP)
{
    $IpPbxContainerIP = Read-Host 'Please enter a valid IP address for the SwyxWare Server container'
}

if (!$IpPbxAdminCredentials) {
    $IpPbxAdminCredentials = Get-Credential -Message "Enter user name and password for a SwyxWare Administrator." 
}


# make sure the host data folders which are mapped into the container exist
mkdir -Path $HostDataFolder\Traces -Force | out-null
mkdir -Path $HostDataFolder\MemoryDumps -Force | out-null
mkdir -Path $HostDataFolder\Licenses -Force | out-null
mkdir -Path $HostDataFolder\CDRs -Force | out-null


$ArgumentList = @(
    "run",
    "-d",
    "--network=$ContainerNetworkName",
    "--ip $IpPbxContainerIP",
    "--hostname $IpPbxContainerName",
    "--name $IpPbxContainerName",
    "-e SQLSERVERINSTANCE=$SQLServerInstance",
    "-e SQLADMINUSER=$SQLAdminName",
    "-e SQLADMINPASSWORD=$((new-object "PSCredential" -ArgumentList "user",$SQLAdminPassword).GetNetworkCredential().Password)",
    "-e IPPBXADMINUSER=$($IpPbxAdminCredentials.Username)",
    "-e IPPBXADMINPASSWORD=$($IpPbxAdminCredentials.GetNetworkCredential().Password)",
    "-e VERBOSE=True",
    "--volume $HostDataFolder\Traces:$ContainerDataFolder\Traces",
    "--volume $HostDataFolder\MemoryDumps:$ContainerDataFolder\MemoryDumps",
    "--volume $HostDataFolder\Licenses:$ContainerDataFolder\Licenses",
    "--volume $HostDataFolder\CDRs:$ContainerDataFolder\CDRs",
    $SwyxWareContainerImageName
)     

$p = start-process -NoNewWindow -Wait -PassThru -FilePath "docker.exe" -ArgumentList $ArgumentList -RedirectStandardError $RedirectOutputFile

if ($p.ExitCode -ne 0)
{   
    Add-LogFromFile -Level Error -FilePath $RedirectOutputFile 
    remove-item -LiteralPath $RedirectOutputFile -Force
    throw "SwyxWare Server container could not be started. Docker run command stopped with exit code '$($p.ExitCode)'."
}
else {
    Add-LogMessage -Level Info -Message "SwyxWare Container started"
}
remove-item -LiteralPath $RedirectOutputFile -Force | out-null

    
    #The container has started and is initialising. This takes some minutess
    Add-LogMessage -Level Info -Message "SwyxWare is being configured. This may take a while..."
    $InitialisationStatus = "configuring"
    while($InitialisationStatus -eq "configuring")
    {
        
        Start-Sleep -Seconds 10
        $ContainerLogLastLines = docker container logs --tail 5 $IpPbxContainerName
        if ($ContainerLogLastLines -match "Configuration completed") 
        {
            $InitialisationStatus = "finished"
        }
        elseif ($ContainerLogLastLines -match"IpPbxConfig failed")
        {
            $InitialisationStatus = "error"
        }        
    }

    if($InitialisationStatus -ne "finished")
    {
        docker container logs $IpPbxContainerName > $RedirectOutputFile
        Add-LogFromFile -Level Info -FilePath $RedirectOutputFile
        Remote-item $RedirectOutputFile -force

        throw "The SwyxWare configuration of '$($ContainerName)' failed."
    }
    else
    {
        Add-LogMessage -Level Info -Message "SwyxWare container '$IpPbxContainerName' has been configured successfully."
    }


# Stop the logging
Add-LogMessage -Level Info -Message "May the force be with you ;-)"
Stop-Logging
