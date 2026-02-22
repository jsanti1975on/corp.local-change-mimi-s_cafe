# ==================================================================================================
# INVENTORY DAILY SNAPSHOT (Production)  |  Standard User Safe
# ==================================================================================================
# PURPOSE:
# Creates a tamper-evident daily snapshot of an inventory workbook by:
#   1) Copying the source file to a timestamped snapshot folder
#   2) Creating a ZIP archive of the snapshot
#   3) Generating SHA256 hashes for BOTH the copied file and the ZIP
#   4) Appending a one-line entry to an audit log CSV
#
# WHY THIS WORKS IN A SHARED ENVIRONMENT:
# - Even with 6+ people touching inventory, you can prove:
#   “This is exactly what the file looked like at the time I ran the snapshot.”
#
# CHANGE LOG:
# v1.0.0  (Production)
# - Initial release: snapshot copy + ZIP + SHA256 + audit log + standard-user paths
#
# RUN AS:
# - Standard user (no admin required)
#
# DEFAULT OUTPUT:
# - D:\Documents\Inventory_Audit\  (falls back to %USERPROFILE%\Documents\Inventory_Audit if D: missing)
# ==================================================================================================
# inventory-daily-snapshot.ps1
param(
  [string]$SourcePath = "",
  [string]$AuditRoot  = "D:\Documents\Inventory_Audit",
  [string]$Label      = "InventorySnapshot"
)

# -------------------------
# Helper: Write + echo
# -------------------------
function Write-Info($msg) {
  $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
  Write-Host "[$ts] $msg"
}

# -------------------------
# Resolve AuditRoot fallback (standard-user safe)
# -------------------------
try {
  if (-not (Test-Path -LiteralPath (Split-Path -Path $AuditRoot -Parent))) {
    # If the drive/path doesn't exist, fall back to user's Documents
    $AuditRoot = Join-Path $env:USERPROFILE "Documents\Inventory_Audit"
  }
} catch {
  $AuditRoot = Join-Path $env:USERPROFILE "Documents\Inventory_Audit"
}

# Ensure audit directories exist
$null = New-Item -ItemType Directory -Path $AuditRoot -Force -ErrorAction SilentlyContinue

# -------------------------
# Ask for source file if not provided
# -------------------------
if ([string]::IsNullOrWhiteSpace($SourcePath)) {
  Write-Host ""
  Write-Host "Enter full path to the inventory workbook (e.g., C:\Path\Inventory.xlsm)"
  Write-Host "Tip: You can drag-drop the file into this PowerShell window to paste the path."
  $SourcePath = Read-Host "SourcePath"
}

# Clean quotes from drag-drop
$SourcePath = $SourcePath.Trim().Trim('"')

if (-not (Test-Path -LiteralPath $SourcePath)) {
  Write-Host ""
  Write-Host "ERROR: Source file not found: $SourcePath" -ForegroundColor Red
  exit 1
}

# -------------------------
# Build dated folder + filenames
# -------------------------
$now        = Get-Date
$yyyy       = $now.ToString("yyyy")
$mm         = $now.ToString("MM")
$dd         = $now.ToString("dd")
$hhmm       = $now.ToString("HHmm")
$stamp      = $now.ToString("yyyy-MM-dd_HHmmss")

$dayRoot    = Join-Path $AuditRoot "$yyyy\$mm\$dd"
$null       = New-Item -ItemType Directory -Path $dayRoot -Force -ErrorAction SilentlyContinue

$sourceItem = Get-Item -LiteralPath $SourcePath
$ext        = $sourceItem.Extension
$base       = [IO.Path]::GetFileNameWithoutExtension($sourceItem.Name)

# Copied snapshot file (exact copy of the workbook at this time)
$snapshotName = "{0}_{1}_{2}{3}" -f $Label, $base, $stamp, $ext
$snapshotPath = Join-Path $dayRoot $snapshotName

# ZIP archive path
$zipName     = "{0}_{1}_{2}.zip" -f $Label, $base, $stamp
$zipPath     = Join-Path $dayRoot $zipName

# Audit log CSV (append-only behavior by convention)
$auditLogPath = Join-Path $AuditRoot "Inventory_Snapshot_AuditLog.csv"

# -------------------------
# Optional transcript (helps prove execution)
# -------------------------
$transcriptPath = Join-Path $dayRoot ("RunTranscript_{0}.txt" -f $stamp)
try { Start-Transcript -Path $transcriptPath -Append | Out-Null } catch {}

Write-Info "Source: $SourcePath"
Write-Info "AuditRoot: $AuditRoot"
Write-Info "DayFolder: $dayRoot"

# -------------------------
# Copy source file to snapshot location
# -------------------------
try {
  Copy-Item -LiteralPath $SourcePath -Destination $snapshotPath -Force
  Write-Info "Snapshot copied: $snapshotPath"
} catch {
  Write-Host "ERROR: Failed to copy snapshot. $($_.Exception.Message)" -ForegroundColor Red
  try { Stop-Transcript | Out-Null } catch {}
  exit 1
}

# -------------------------
# Create ZIP containing the snapshot file
# -------------------------
try {
  if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
  Compress-Archive -LiteralPath $snapshotPath -DestinationPath $zipPath -Force
  Write-Info "ZIP created: $zipPath"
} catch {
  Write-Host "ERROR: Failed to create ZIP. $($_.Exception.Message)" -ForegroundColor Red
  try { Stop-Transcript | Out-Null } catch {}
  exit 1
}

# -------------------------
# Generate SHA256 hashes (tamper-evident)
# -------------------------
try {
  $hashSnapshot = (Get-FileHash -Algorithm SHA256 -LiteralPath $snapshotPath).Hash
  $hashZip      = (Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath).Hash
  Write-Info "SHA256 Snapshot: $hashSnapshot"
  Write-Info "SHA256 ZIP     : $hashZip"
} catch {
  Write-Host "ERROR: Failed to hash files. $($_.Exception.Message)" -ForegroundColor Red
  try { Stop-Transcript | Out-Null } catch {}
  exit 1
}

# -------------------------
# Append audit record (CSV)
# -------------------------
$record = [pscustomobject]@{
  Timestamp          = $now.ToString("yyyy-MM-dd HH:mm:ss")
  User               = $env:USERNAME
  Computer           = $env:COMPUTERNAME
  SourcePath         = $SourcePath
  SourceLastWrite    = $sourceItem.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
  SnapshotPath       = $snapshotPath
  ZipPath            = $zipPath
  SnapshotSHA256     = $hashSnapshot
  ZipSHA256          = $hashZip
}

try {
  $exists = Test-Path -LiteralPath $auditLogPath
  if (-not $exists) {
    $record | Export-Csv -LiteralPath $auditLogPath -NoTypeInformation
    Write-Info "Audit log created: $auditLogPath"
  } else {
    $record | Export-Csv -LiteralPath $auditLogPath -NoTypeInformation -Append
    Write-Info "Audit log appended: $auditLogPath"
  }
} catch {
  Write-Host "WARNING: Snapshot completed but audit log write failed. $($_.Exception.Message)" -ForegroundColor Yellow
}

# -------------------------
# Quick integrity check (optional, lightweight)
# -------------------------
try {
  $verifyZip = (Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath).Hash
  if ($verifyZip -ne $hashZip) {
    Write-Host "WARNING: ZIP hash mismatch on re-read. Investigate storage reliability." -ForegroundColor Yellow
  } else {
    Write-Info "Verification OK (ZIP hash re-read matches)."
  }
} catch {
  Write-Host "WARNING: Could not verify ZIP hash. $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Info "DONE. Daily snapshot is complete."
try { Stop-Transcript | Out-Null } catch {}
# ==================================================================================================
