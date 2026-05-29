# ================================
# Failed Login Investigation Script
# ================================

Write-Host "Collecting failed login attempts..." -ForegroundColor Cyan

# Event ID 4625 = Failed logon
$events = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4625
    StartTime=(Get-Date).AddHours(-24)
} -ErrorAction SilentlyContinue

if (!$events) {
    Write-Host "No failed login events found." -ForegroundColor Yellow
    exit
}

$results = foreach ($event in $events) {

    $xml = [xml]$event.ToXml()

    $data = @{}
    foreach ($item in $xml.Event.EventData.Data) {
        $data[$item.Name] = $item.'#text'
    }

    [PSCustomObject]@{
        TimeCreated      = $event.TimeCreated
        TargetUser       = $data['TargetUserName']
        TargetDomain     = $data['TargetDomainName']
        SourceIP         = $data['IpAddress']
        Workstation      = $data['WorkstationName']
        LogonType        = $data['LogonType']
        FailureReason    = $data['FailureReason']
        Status           = $data['Status']
        SubStatus        = $data['SubStatus']
        ProcessName      = $data['ProcessName']
    }
}

# Show detailed events
Write-Host "`n===== Detailed Failed Login Attempts =====" -ForegroundColor Red
$results |
Sort-Object TimeCreated -Descending |
Format-Table -AutoSize

# Top attacked accounts
Write-Host "`n===== Top Targeted Accounts =====" -ForegroundColor Cyan
$results |
Group-Object TargetUser |
Sort-Object Count -Descending |
Select-Object Count, Name |
Format-Table -AutoSize

# Top source IPs
Write-Host "`n===== Top Source IPs =====" -ForegroundColor Cyan
$results |
Where-Object { $_.SourceIP -and $_.SourceIP -ne "-" } |
Group-Object SourceIP |
Sort-Object Count -Descending |
Select-Object Count, Name |
Format-Table -AutoSize