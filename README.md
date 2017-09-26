# SwyxWare 11 Docker Technology Preview

This repository provides everything necessary to build a SwyxWare 11 Windows Container image. The image contains all SwyxWare services (except SwyxGate) in one image

This is a technical preview, not a production-ready version.

## How to run the image

To easily deploy the SwyxWare image and a SQLExpress image run the ````Start-IpPbxDockerDeployment.ps1```` script from an elevated PowerShell prompt on a Windows Server 2016 system. It will do the following:

1. Prompt for all necessary information like IP addresses, SQL and SwyxWare Credentials
1. Enable Docker on the server if not already present
1. Pull Operating System Base Image 
1. Create a transparent container network on the host
1. Start the SQLExpress and SwyxWare image

__To run and configure the image manuall see the following instructions.__

## Environment Variables

The SwyxWare image supports a couple of parameters you have set when running the image manually

| Environment Variable | Required |Default when not net |Description |
|-|-|-|-|
|SQLSERVERINSTANCE|yes| -| Name of sqlserver instance. |
|SQLADMINUSER|no|"sa"|SQL Admin login name (used to create/update SwyxWare Database)|
|SQLADMINPASSWORD|yes|-|SQL Admin login password|
|SQLIPPBXDATABASENAME|no|"ippbx"|SwyxWare Database name|
|SQLIPPBXUSER|no|"ippbx_user"|SwyxWare Database SQL Login. Used by SwyxWare to access the database|
|SQLIPPBXPASSWORD|no|(random)|SwyxWare Database SQL login password. Random password is created when not set |
|IPPBXADMINUSER|no|(none)|SwyxWare Administrator user name. If not set no SwyxWare Administrator will be created|
|IPPBXADMINPASSWORD|no|(none)|SwyXWare Administrator password.If not set no SwyxWare Administrator will be created|
|VERBOSE|no|false|Verbose logging. IpPbxConfig.exe log will be logged to container log if set

## Data Volumes

The SwyxWare image automatically creates docker data volumes for the following container folder.

|Folder|Description|
|-|-|
|c:\programdata\swyx\traces|Traces files|
|c:\programdata\swyx\memorydumps|swyxware process memeory dumps|
|c:\programdata\swyx\licenses|licenses|
|c:\programdata\swyx\CDRs|Call Detail Records|

if nothing is specified when running the container docker automatically creates volumes with random ID. It is therefore recommended to either specify folder mappings on the command line or created names volumes. See below for details

### Map host folder

To map the above mentioned container folder to folders on the host specify appropriate mappings on the docker run command line, e.g.

(Note: The commandline omits specifying required environment variables, network name, container and host name for brevity)

    docker run --volume C:\data\Traces:c:\ProgramData\Swyx\Traces --volume C:\data\MemoryDumps:c:\ProgramData\Swyx\MemoryDumps --volume C:\data\Licenses:c:\ProgramData\Swyx\Licenses --volume C:\data\CDRs:c:\ProgramData\Swyx\CDRs swyx/swyxware-cpe:11.00

### Use named data volume

Instead of mapping host folders you can create named docker volumes like this:

    docker volume create ippbxtraces
    docker volume create ippbxdumps
    docker volume create ippbxlicense
    docker volume create ippbxcdrs

then specify the volumes on the docker run command line

(Note: The commandline omits to specify required environment variables, network name, container and host name for brevity)

    docker run --volume ippbxtraces:c:\ProgramData\Swyx\Traces --volume ippbxdumps:c:\ProgramData\Swyx\MemoryDumps --volume ippbxlicenses:c:\ProgramData\Swyx\Licenses --volume ippbxcdrs:c:\ProgramData\Swyx\CDRs swyx/swyxware-cpe:11.00


## Transparent Container Network

The SwyxWare Container requires a transparent network without NAT. You create it using the docker network command. A transparent network requires to define a subnet and default gateway. The subnet has to be the same or smaller than the hosts subnet. The default gateway usually is the same as the hosts default gateway.

### Create a transparent container network

Create a transparent docker network named "ippxnet" with subnet 192.168.100/24, default gateway 192.168.100.1:

    docker network create --driver=transparent --ipv6=false --subnet=192.168.100.0/24 --gateway=192.168.100.1 ippbxnet

Run run the SwyxWar container in that network specify parameter ````--network=ippbxnet```` on the docker run command line
