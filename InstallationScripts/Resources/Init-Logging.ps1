<# 
.SYNOPSIS 
Initialize log4net module

.PARAMETER LogFile
File to log into.

.PARAMETER LogThreshold
Logging threshold
#> 

# load required .NET assemblies
$ScriptDir = (split-path $MyInvocation.MyCommand.Path -Parent)
$Log4NetLibPath = join-path $ScriptDir "log4net.dll"
Write-Verbose "Loading Log4Net Lib ($($Log4NetLibPath))..."
[void][Reflection.Assembly]::LoadFrom($Log4NetLibPath)

function Init-Logging($targetpath, [log4net.Core.Level]$threshold, [switch]$append=$true)
{
   $logPatternFile = "%date{HH:mm:ss,fff} %-6level%message%newline"
   $logPatternConsole = "%-5level: %message%newline"
   $Log4NetHome = convert-path '.'
   
   $AppenderConfig = [xml]@"
<?xml version="1.0" encoding="utf-8" ?>
<log4net>
   <appender name="ColoredConsoleAppender" type="log4net.Appender.ColoredConsoleAppender">
       <mapping>
           <level value="ERROR" />
           <foreColor value="Red, HighIntensity" />
       </mapping>
       <layout type="log4net.Layout.PatternLayout">
           <conversionPattern value="$logPatternConsole" />
       </layout>
        <threshold value="$threshold" />
    </appender>
    <appender name="FileAppender" type="log4net.Appender.FileAppender">
        <file value="$targetpath" />
        <appendToFile value="$append" />
        <layout type="log4net.Layout.PatternLayout">
            <conversionPattern value="$logpatternFile" />
        </layout>
        <threshold value="DEBUG" />
    </appender>
    <root>
        <level value="DEBUG" />
        <appender-ref ref="ColoredConsoleAppender" />
        <appender-ref ref="FileAppender" />
    </root>
</log4net>    
"@

   [log4net.Config.XmlConfigurator]::Configure($AppenderConfig.log4net)

   # set logger variable for the script to use
   $script:Log = [log4net.LogManager]::GetLogger($Host.GetType())
}


function Stop-Logging
{
   [log4net.LogManager]::Shutdown()
}

function Add-LogMessage
{
    param(
        [string][ValidateSet("Fatal","Error","Warn","Info","Verbose")]$Level = "Info",
        [parameter(Mandatory=$true,ValueFromPipeline=$true)]$Message,
        [switch]$ThrowException = $false
    )
    
    switch ($level)
    {
        "Fatal"   { $Log.Fatal($Message) }
        "Error"   { $Log.Error($Message) }
        "Warn"    { $Log.Warn($Message)  }
        "Info"    { $Log.Info($Message)  }
        "Verbose" { $Log.Debug($Message)  }
    }
    
    # log4net console logger does not output to Powershell ISE. 
    if ($host.name -eq "Windows Powershell ISE Host")
    {
        switch ($level)
        {
            "Fatal"    { Write-Error $Message   }
            "Error"    { Write-Error $Message   }
            "Warn"     { Write-Warning $Message }
            "Info"     { Write-Host $Message    }
            "Verbose"  { Write-Verbose $Message }
        }
    }   
    
    if ($ThrowExeption) {
        throw $Message
    }
}

function Add-LogFromFile
{
    param(
        [string]$Level = "Info",
	    [parameter(Mandatory=$true,ValueFromPipeline=$true)]$FilePath 
    )

    Get-Content -Path $FilePath | ForEach-Object { Add-LogMessage -Level $Level -Message $_ }
}