$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Start-Process "$Root\inbox\google_takeout"
Start-Process "$Root\inbox\whatsapp_exports"
Start-Process "https://takeout.google.com/"
Write-Host "Depois rode: python -m localvault ingest-all --root `"$Root`""
