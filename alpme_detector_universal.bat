<# :
@echo off
title Alpme Forensic Auditor (Universal Edition)
color 0B
powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ((Get-Content -Raw '%~f0') -replace '(?s)^<#.*?#>\r?\n','')"
pause
exit /b
#>

Clear-Host
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "    ALPME EXTENSION FORENSIC AUDITOR (UNIVERSAL)        " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

# 1. Dynamic Auto-Discovery of all VS Code Forks (Antigravity, Cursor, Windsurf, VSCodium, Code)
Write-Host "[*] Auto-discovering installed IDE databases in AppData..." -ForegroundColor Gray

$dbPaths = Get-ChildItem -Path $env:APPDATA -Filter "state.vscdb" -Recurse -Depth 4 -ErrorAction SilentlyContinue | 
           Where-Object { $_.FullName -like "*\globalStorage\state.vscdb" } | 
           Select-Object -ExpandProperty FullName

# Fallback check for common paths if depth scan misses anything
$fallbackPaths = @(
    "$env:APPDATA\Code\User\globalStorage\state.vscdb",
    "$env:APPDATA\Antigravity\User\globalStorage\state.vscdb",
    "$env:APPDATA\Cursor\User\globalStorage\state.vscdb",
    "$env:APPDATA\Windsurf\User\globalStorage\state.vscdb",
    "$env:APPDATA\VSCodium\User\globalStorage\state.vscdb",
    "$env:APPDATA\Code - Insiders\User\globalStorage\state.vscdb"
)
foreach ($fb in $fallbackPaths) {
    if ((Test-Path $fb) -and ($dbPaths -notcontains $fb)) {
        $dbPaths += $fb
    }
}

$discoveredPayloads = [System.Collections.Generic.HashSet[string]]::new()
$discoveredHashes   = [System.Collections.Generic.HashSet[string]]::new()

# Audit Discovered Databases
foreach ($db in $dbPaths) {
    if (Test-Path $db) {
        Write-Host "  [+] Auditing IDE Database: " -NoNewline -ForegroundColor Gray
        Write-Host $db -ForegroundColor White
        try {
            $fs = [System.IO.File]::Open($db, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            $ms = New-Object System.IO.MemoryStream
            $fs.CopyTo($ms)
            $fs.Close()
            $text = [System.Text.Encoding]::ASCII.GetString($ms.ToArray())

            if ($text -match "alpme") {
                # Harvest all historical payload paths
                $pathMatches = [regex]::Matches($text, '([A-Za-z]:\\[^"''\r\n\x00]+\\[0-9a-zA-Z_-]+\.exe)')
                foreach ($m in $pathMatches) {
                    $val = $m.Groups[1].Value.Trim()
                    if ($val -like "*\Temp\*" -or $val -like "*\pkg-*" -or $val -like "*\winhlp-*") {
                        $discoveredPayloads.Add($val) | Out-Null
                    }
                }

                # Anchored Hash Search: Pull SHA-256 tied to partnerSoftware
                $hashMatches = [regex]::Matches($text, 'partnerSoftware[^\da-fA-F]{1,100}([a-fA-F0-9]{64})')
                foreach ($h in $hashMatches) {
                    $discoveredHashes.Add($h.Groups[1].Value) | Out-Null
                }
            }
        } catch {
            Write-Host "      [-] Database locked or inaccessible." -ForegroundColor DarkGray
        }
    }
}

# Display Database Results
if ($discoveredPayloads.Count -gt 0 -or $discoveredHashes.Count -gt 0) {
    Write-Host "`n[!] INFECTION EVIDENCE FOUND IN IDE DATABASE!" -ForegroundColor Red
    
    if ($discoveredPayloads.Count -gt 0) {
        Write-Host "  [-] Recorded Payload Paths:" -ForegroundColor Yellow
        foreach ($p in $discoveredPayloads) {
            $exists = Test-Path $p
            Write-Host "      $p " -NoNewline -ForegroundColor White
            if ($exists) {
                Write-Host "[STILL ON DISK!]" -ForegroundColor Red
            } else {
                Write-Host "[Purged]" -ForegroundColor DarkGray
            }
        }
    }

    if ($discoveredHashes.Count -gt 0) {
        Write-Host "  [-] Extracted Malware Hashes (VirusTotal Links):" -ForegroundColor Yellow
        foreach ($h in $discoveredHashes) {
            Write-Host "      Hash : $h" -ForegroundColor White
            Write-Host "      Link : https://www.virustotal.com/gui/file/$h" -ForegroundColor Cyan
        }
    }
} else {
    Write-Host "[+] All IDE Databases Clean: No Alpme dropper records found." -ForegroundColor Green
}

# 2. Universal Memory Hunter (Defensive Try/Catch Path Resolution)
Write-Host "`n[*] Scanning active processes for malware running from Temp..." -ForegroundColor Gray
$tempNormalized = try { [System.IO.Path]::GetFullPath($env:TEMP).ToLower() } catch { $env:TEMP.ToLower() }

$rogueProcs = Get-CimInstance Win32_Process | Where-Object {
    $exe = $_.ExecutablePath
    if ($exe) {
        $exeLower = try { [System.IO.Path]::GetFullPath($exe).ToLower() } catch { $exe.ToLower() }
        
        ($exeLower.StartsWith($tempNormalized) -and ($_.Name -match '^[0-9]+si\.exe$' -or $_.Name -match '^(svchost|wuauclt|winhlp|pkg)[-_]')) -or
        ($_.Name -match '^[0-9]+si\.exe$') -or 
        ($_.Name -match '^(svchost|wuauclt|winhlp|pkg)[-_][0-9a-fA-F]{4,14}\.exe$')
    } else {
        $false
    }
}

if ($rogueProcs) {
    foreach ($p in $rogueProcs) {
        Write-Host "[!] ACTIVE MALWARE RUNNING IN MEMORY: $($p.Name) (PID: $($p.ProcessId))" -ForegroundColor Red
        Write-Host "    Location: $($p.ExecutablePath)" -ForegroundColor Yellow
    }
} else {
    Write-Host "[+] Memory Clean: Zero processes running from Temp or matching malware signatures." -ForegroundColor Green
}

# 3. Surgical %TEMP% Scanner (Requires .EXE + Exact Malware Signatures)
Write-Host "`n[*] Recursively scanning %TEMP% for dropped payload binaries..." -ForegroundColor Gray
$malwareFiles = Get-ChildItem -Path $env:TEMP -Recurse -File -Depth 3 -ErrorAction SilentlyContinue | Where-Object {
    if ($_.Extension -ne ".exe") { return $false }

    $folder = $_.Directory.Name
    $isMalwareFolder = $folder -match '^(svchost|wuauclt|winhlp|pkg)[-_][0-9a-fA-F]{4,14}$'
    $isDisguiseExe   = $_.Name -match '^(svchost|wuauclt|winhlp|pkg)[-_][0-9a-fA-F]{4,14}\.exe$'
    $isSiPayload     = $_.Name -match '^[0-9]+si\.exe$'

    $isSiPayload -or $isDisguiseExe -or $isMalwareFolder
}

if ($malwareFiles) {
    foreach ($f in $malwareFiles) {
        Write-Host "[!] DROPPED MALWARE FOUND ON DISK: $($f.FullName)" -ForegroundColor Red
    }
} else {
    Write-Host "[+] %TEMP% Clean: No payload files found in root or subdirectories." -ForegroundColor Green
}

Write-Host "`nAudit completed." -ForegroundColor Cyan
