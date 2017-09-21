## SwyxWare 11 Docker Technology Preview

This repository provides everything necessary to build a SwyxWare 11 Windows Container image. The image contains all SwyxWare services (except SwyxGate) in one image

This is a technical preview, not a production-ready version.

### How to run the image

To easily deploy the SwyxWare image and a SQLExpress image run the ````Start-IpPbxDockerDeployment.ps1 ```` script from an elevated PowerShell prompt on a Windows Server 2016 system. It will do the following:

1. Prompt for all necessary information like IP addresses, SQL and SwyxWare Credentials
1. Enable Docker on the server if not already present
1. Pull Operating System Base Image 
1. Create a transparent container network on the host
1. Start the SQLExpress and SwyxWare image
