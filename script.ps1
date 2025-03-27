# Ensure the script runs as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator!" -ForegroundColor Red
    exit
}

Write-Host "Starting System Maintenance..." -ForegroundColor Cyan

# Define log file paths
$MonitoringLog = "C:\System_Monitoring_Log.txt"
$SecurityLog = "C:\Monitoring\Security_System_Logs.csv"
$MonitoringDir = "C:\Monitoring"
$Interval = 10

# Ensure monitoring directory exists
if (!(Test-Path -Path $MonitoringDir)) {
    New-Item -ItemType Directory -Path $MonitoringDir | Out-Null
}

##########################
# Function: Monitor System Usage
##########################
function Get-SystemUsage {
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $CPU = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
    $TotalMemory = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB
    $FreeMemory = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB
    $UsedMemory = $TotalMemory - $FreeMemory
    $MemoryUsagePercent = ($UsedMemory / $TotalMemory) * 100
    $Disk = Get-PSDrive C | Select-Object Used, Free
    $DiskUsed = $Disk.Used / 1GB
    $DiskFree = $Disk.Free / 1GB
    $DiskUsagePercent = ($DiskUsed / ($DiskUsed + $DiskFree)) * 100
    
    $LogEntry = "[$TimeStamp] CPU: {0:N2}% | Memory: {1:N2}% ({2:N2}GB used of {3:N2}GB) | Disk: {4:N2}% ({5:N2}GB used of {6:N2}GB)" -f `
                $CPU, $MemoryUsagePercent, $UsedMemory, $TotalMemory, $DiskUsagePercent, $DiskUsed, ($DiskUsed + $DiskFree)
    Write-Output $LogEntry
    Add-Content -Path $MonitoringLog -Value $LogEntry
}

##########################
# Function: Analyze Logs
##########################
function Analyze-Logs {
    Write-Host "Fetching Security and System logs..."
    $StartTime = (Get-Date).AddHours(-24)
    
    $SecurityLogs = Get-WinEvent -LogName Security -FilterXPath "*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]" -ErrorAction SilentlyContinue |
                    Where-Object { $_.Id -in (4625, 4740, 4768, 4771, 4776) } |
                    Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message
    
    $SystemLogs = Get-WinEvent -LogName System -FilterXPath "*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]" -ErrorAction SilentlyContinue |
                    Where-Object { $_.Level -in (1, 2) } |
                    Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message
    
    $AllLogs = $SecurityLogs + $SystemLogs
    if ($AllLogs) {
        $AllLogs | Export-Csv -Path $SecurityLog -NoTypeInformation -Encoding UTF8
        Write-Host "Log analysis completed. Results saved to $SecurityLog"
    } else {
        Write-Host "No significant security or system logs found."
    }
}

##########################
# Function: Clean TEMP Files
##########################
function Clean-TempFiles {
    Write-Host "Cleaning Temporary Files..."
    $TempPaths = @("$env:TEMP", "C:\Windows\Temp")
    foreach ($path in $TempPaths) {
        if (Test-Path $path) {
            try {
                Get-ChildItem -Path $path -Recurse -Force | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                Write-Host "✅ Cleaned: $path" -ForegroundColor Green
            } catch {
                Write-Host "❌ Failed to clean: $path. Error: $_" -ForegroundColor Red
            }
        }
    }
}

##########################
# Function: Restart Essential Services
##########################
function Restart-Services {
    Write-Host "Restarting Essential Services..."
    $Services = @("wuauserv", "bits", "Dnscache", "Spooler", "Winmgmt")
    foreach ($service in $Services) {
        if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
            try {
                Restart-Service -Name $service -Force
                Write-Host "✅ Restarted: $service" -ForegroundColor Green
            } catch {
                Write-Host "❌ Failed to restart: $service. Error: $_" -ForegroundColor Red
            }
        }
    }
}

##########################
# Function: Install Windows Updates
##########################
function Install-WindowsUpdates {
    Write-Host "Checking for Windows Updates..."
    if (-not (Get-Module -Name PSWindowsUpdate -ListAvailable)) {
        Write-Host "Installing Windows Update module..."
        Install-Module PSWindowsUpdate -Force -Confirm:$false
    }
    Import-Module PSWindowsUpdate
    try {
        Get-WindowsUpdate -Install -AcceptAll -AutoReboot
        Write-Host "✅ Windows Updates Installed Successfully!"
    } catch {
        Write-Host "❌ Failed to install updates. Error: $_"
    }
}

##########################
# Run All Tasks
##########################
Write-Host "System monitoring started. Logging every $Interval seconds..."
Start-Job -ScriptBlock {
    while ($true) {
        Get-SystemUsage
        Start-Sleep -Seconds $Interval
    }
}

Analyze-Logs
Clean-TempFiles
Restart-Services
Install-WindowsUpdates

Write-Host "🚀 System Maintenance Complete! 🚀" -ForegroundColor Green
