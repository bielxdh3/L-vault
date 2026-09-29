[CmdletBinding()]
param(
    [switch]$BuildOnly,
    [switch]$Install,
    [switch]$SelfCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# This must be replaced with the production code-signing certificate thumbprint
# before a release. Installation intentionally fails while it is unset.
$script:ReleaseSignerThumbprint = 'SET_IN_RELEASE_BUILD'
$script:RepoRoot = 'E:\LocalVault'
$script:WorkerSource = Join-Path $script:RepoRoot 'tools\clone_worker_entry.py'
$script:NativeProject = Join-Path $script:RepoRoot 'native\vss_snapshot\Cargo.toml'
$script:NativeRelease = Join-Path $script:RepoRoot 'native\vss_snapshot\target\x86_64-pc-windows-msvc\release\LVaultVssSnapshot.exe'
$script:StageRoot = Join-Path $script:RepoRoot '.build\clone-runtime-stage'
$script:BundleRoot = Join-Path $script:StageRoot 'bundle'
$script:WorkerStaged = Join-Path $script:BundleRoot 'LocalVaultCloneWorker.exe'
$script:VssStaged = Join-Path $script:BundleRoot 'LVaultVssSnapshot.exe'
$script:AppRoot = 'C:\ProgramData\L-vault'
$script:RuntimeRoot = Join-Path $script:AppRoot 'clone-runtime'
$script:RuntimeTemp = Join-Path $script:RuntimeRoot 'Temp'
$script:StateRoot = Join-Path $script:AppRoot 'clone-state'
$script:WorkerInstalled = Join-Path $script:RuntimeRoot 'LocalVaultCloneWorker.exe'
$script:VssInstalled = Join-Path $script:RuntimeRoot 'LVaultVssSnapshot.exe'
$script:OwnerSidPath = Join-Path $script:StateRoot 'owner.sid'

$script:SystemSid = 'S-1-5-18'
$script:AdministratorsSid = 'S-1-5-32-544'
$script:UsersSid = 'S-1-5-32-545'
$script:CreatorOwnerSid = 'S-1-3-0'
$script:OwnerRightsSid = 'S-1-3-4'
$script:FullControlMask = 0x001F01FFL
$script:ReadExecuteMask = 0x001200A9L
$script:UnsafeUserWriteMask = 0x500D0156L

function Test-IsAdministrator {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-NoReparseChain([string]$LiteralPath, [switch]$AllowMissingLeaf) {
    $full = [IO.Path]::GetFullPath($LiteralPath)
    $root = [IO.Path]::GetPathRoot($full)
    $relative = $full.Substring($root.Length)
    $parts = @($relative -split '[\\/]+' | Where-Object { $_ })
    $current = $root
    for ($index = 0; $index -lt $parts.Count; $index++) {
        $current = Join-Path $current $parts[$index]
        if (-not [IO.File]::Exists($current) -and -not [IO.Directory]::Exists($current)) {
            if ($AllowMissingLeaf -and $index -eq ($parts.Count - 1)) { return }
            if ($AllowMissingLeaf -and $index -ge ($parts.Count - 1)) { return }
            throw "Required path component is missing: $current"
        }
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Reparse point in trusted path: $current"
        }
    }
}

function New-CloneDirectorySecurity {
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $none = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $deny = [Security.AccessControl.AccessControlType]::Deny
    $full = [Security.AccessControl.FileSystemRights]::FullControl
    $readExecute = [Security.AccessControl.FileSystemRights]::ReadAndExecute
    foreach ($sid in @($script:SystemSid, $script:AdministratorsSid)) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), $full, $inherit, $none, $allow
        ))
    }
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($script:UsersSid), $readExecute, $inherit, $none, $allow
    ))
    $ownerControl = [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($script:OwnerRightsSid), $ownerControl, $inherit, $none, $deny
    ))
    return $security
}

function Assert-SafeCloneAcl([string]$LiteralPath, [switch]$RequireProtected) {
    $acl = Get-Acl -LiteralPath $LiteralPath
    if ($RequireProtected -and -not $acl.AreAccessRulesProtected) {
        throw "DACL inheritance is not disabled on protected directory: $LiteralPath"
    }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -eq 0) { throw "No DACL entries found: $LiteralPath" }
    $masks = @{}
    $ownerRightsDeny = 0L
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if ($sid -eq $script:OwnerRightsSid) {
            $mask = [long]$rule.FileSystemRights
            if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Deny -or
                ($mask -band 0x000C0000L) -ne 0x000C0000L) {
                throw "Owner Rights must deny WRITE_DAC and WRITE_OWNER: $LiteralPath"
            }
            $ownerRightsDeny = $ownerRightsDeny -bor $mask
            continue
        }
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw "Unexpected deny ACE in protected runtime: $LiteralPath"
        }
        if ($sid -notin @($script:SystemSid, $script:AdministratorsSid, $script:UsersSid)) {
            throw "Unexpected DACL principal $sid on $LiteralPath"
        }
        $masks[$sid] = [long]$masks[$sid] -bor [long]$rule.FileSystemRights
    }
    if (($ownerRightsDeny -band 0x000C0000L) -ne 0x000C0000L) {
        throw "Owner Rights cannot change the DACL or owner: $LiteralPath"
    }
    foreach ($sid in @($script:SystemSid, $script:AdministratorsSid)) {
        if (([long]$masks[$sid] -band $script:FullControlMask) -ne $script:FullControlMask) {
            throw "SYSTEM/Administrators do not have full control: $LiteralPath"
        }
    }
    $userMask = [long]$masks[$script:UsersSid]
    if (($userMask -band $script:ReadExecuteMask) -ne $script:ReadExecuteMask -or
        ($userMask -band $script:UnsafeUserWriteMask) -ne 0) {
        throw "Interactive users lack read/execute or have write access: $LiteralPath"
    }
}

function Assert-ProgramDataAncestors {
    $replaceMask = 0x500D0040L # DELETE_CHILD, DELETE, WRITE_DAC/OWNER, GENERIC_WRITE/ALL
    $standardSids = @('S-1-1-0', 'S-1-2-0', 'S-1-5-4', 'S-1-5-7', 'S-1-5-11', 'S-1-5-12', $script:UsersSid, 'S-1-5-32-547')
    foreach ($path in @('C:\', 'C:\ProgramData')) {
        Assert-NoReparseChain $path
        $item = Get-Item -LiteralPath $path -Force
        if (-not $item.PSIsContainer) { throw "Windows ancestor is not a directory: $path" }
        $acl = Get-Acl -LiteralPath $path
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -in $standardSids) { throw "Standard users own a ProgramData ancestor: $path" }
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            $sid = $rule.IdentityReference.Value
            if ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
            if ($sid -eq $script:CreatorOwnerSid) { throw "Creator Owner ACE applies to the ancestor itself: $path" }
            if ($sid -in $standardSids -and $rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny) {
                throw "Unexpected deny ACE for a standard principal on $path"
            }
            $unclassified = $sid -notin ($standardSids + @($script:SystemSid, $script:AdministratorsSid, $script:CreatorOwnerSid))
            if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                ($sid -in $standardSids -or $unclassified) -and
                ([long]$rule.FileSystemRights -band $replaceMask) -ne 0) {
                throw "A standard or unclassified principal can delete/replace a child of $path"
            }
        }
    }
}

function Ensure-CloneDirectory([string]$LiteralPath) {
    Assert-NoReparseChain $LiteralPath -AllowMissingLeaf
    if ([IO.Directory]::Exists($LiteralPath)) {
        Assert-SafeCloneAcl $LiteralPath -RequireProtected
        return
    }
    $security = New-CloneDirectorySecurity
    [void][IO.Directory]::CreateDirectory($LiteralPath, $security)
    Assert-NoReparseChain $LiteralPath
    Assert-SafeCloneAcl $LiteralPath -RequireProtected
}

function Assert-SourceTree {
    Assert-NoReparseChain $script:RepoRoot
    foreach ($path in @($script:WorkerSource, $script:NativeProject)) {
        Assert-NoReparseChain $path
        if (-not [IO.File]::Exists($path)) { throw "Required build source is missing: $path" }
    }
}

function Get-SignerThumbprint([string]$LiteralPath) {
    Assert-NoReparseChain $LiteralPath
    $signature = Get-AuthenticodeSignature -LiteralPath $LiteralPath
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or -not $signature.SignerCertificate) {
        throw "A valid trusted Authenticode signature is required: $LiteralPath"
    }
    return ($signature.SignerCertificate.Thumbprint -replace '\s', '').ToUpperInvariant()
}

function Assert-ReleaseSignature([string]$LiteralPath) {
    if ($script:ReleaseSignerThumbprint -notmatch '^[A-Fa-f0-9]{40}$') {
        throw 'Install is disabled until the production release signer thumbprint is pinned in this script.'
    }
    $actual = Get-SignerThumbprint $LiteralPath
    if ($actual -ne $script:ReleaseSignerThumbprint.ToUpperInvariant()) {
        throw "Unexpected release signer for $LiteralPath"
    }
}

function Invoke-BuildOnly {
    if (Test-IsAdministrator) { throw 'BuildOnly must run unelevated; do not execute user-writable build tools as administrator.' }
    if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit PowerShell to build the Windows x64 runtime.' }
    Assert-SourceTree
    $entrySelfCheck = Get-Command py.exe -ErrorAction Stop
    $cargoCommand = Get-Command cargo.exe -ErrorAction Stop
    $py = $entrySelfCheck.Source
    $cargo = $cargoCommand.Source
    foreach ($directory in @($script:StageRoot, $script:BundleRoot, (Join-Path $script:StageRoot 'work'), (Join-Path $script:StageRoot 'spec'))) {
        if (-not [IO.Directory]::Exists($directory)) { [void][IO.Directory]::CreateDirectory($directory) }
        Assert-NoReparseChain $directory
    }

    & $py -3 $script:WorkerSource --self-check
    if ($LASTEXITCODE -ne 0) { throw 'Worker entrypoint contract self-check failed.' }

    & $py -3 -m PyInstaller --noconfirm --clean --onefile --noconsole `
        --name LocalVaultCloneWorker `
        --paths (Join-Path $script:RepoRoot 'src') `
        --hidden-import localvault.first_party_clone_worker `
        --hidden-import localvault.first_party_data_clone `
        --hidden-import localvault.clone_runtime_security `
        --runtime-tmpdir $script:RuntimeTemp `
        --distpath $script:BundleRoot `
        --workpath (Join-Path $script:StageRoot 'work') `
        --specpath (Join-Path $script:StageRoot 'spec') `
        $script:WorkerSource
    if ($LASTEXITCODE -ne 0 -or -not [IO.File]::Exists($script:WorkerStaged)) { throw 'PyInstaller did not produce the worker artifact.' }

    & $cargo build --release --target x86_64-pc-windows-msvc --manifest-path $script:NativeProject
    if ($LASTEXITCODE -ne 0 -or -not [IO.File]::Exists($script:NativeRelease)) { throw 'Cargo did not produce the VSS helper artifact.' }
    Copy-Item -LiteralPath $script:NativeRelease -Destination $script:VssStaged -Force

    $manifest = [ordered]@{
        schema = 1
        repository = $script:RepoRoot
        commit = (& git -C $script:RepoRoot rev-parse HEAD 2>$null | Out-String).Trim()
        worker_sha256 = (Get-FileHash -LiteralPath $script:WorkerStaged -Algorithm SHA256).Hash
        vss_helper_sha256 = (Get-FileHash -LiteralPath $script:VssStaged -Algorithm SHA256).Hash
        worker_artifact = [IO.Path]::GetFileName($script:WorkerStaged)
        vss_helper_artifact = [IO.Path]::GetFileName($script:VssStaged)
        python = (& $py -3 --version 2>&1 | Out-String).Trim()
        cargo = (& $cargo --version 2>&1 | Out-String).Trim()
        build_time_utc = [DateTime]::UtcNow.ToString('o')
        status = 'unsigned-development-build; installation disabled'
    }
    $manifestPath = Join-Path $script:BundleRoot 'build-manifest.json'
    [IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
    Assert-NoReparseChain $manifestPath
    Write-Output "Build-only artifacts are ready at $script:BundleRoot"
    Write-Output 'Do not use these unsigned development artifacts for privileged installation.'
}

function Install-CloneRuntime {
    if (-not (Test-IsAdministrator)) { throw 'Install requires one elevated PowerShell session.' }
    if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit elevated PowerShell.' }
    Assert-SourceTree
    Assert-ProgramDataAncestors
    foreach ($path in @($script:WorkerStaged, $script:VssStaged)) {
        if (-not [IO.File]::Exists($path)) { throw "Signed release artifact is missing: $path" }
        Assert-ReleaseSignature $path
    }

    # If a previous path exists it must already be secure. Never take over a
    # user-writable directory that may contain untrusted plans or helper files.
    Ensure-CloneDirectory $script:AppRoot
    Ensure-CloneDirectory $script:RuntimeRoot
    Ensure-CloneDirectory $script:RuntimeTemp
    Ensure-CloneDirectory $script:StateRoot

    $ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ([IO.File]::Exists($script:OwnerSidPath)) {
        Assert-NoReparseChain $script:OwnerSidPath
        Assert-SafeCloneAcl $script:OwnerSidPath
        $existingSid = [IO.File]::ReadAllText($script:OwnerSidPath, [Text.Encoding]::ASCII).Trim()
        if ($existingSid -ne $ownerSid) { throw 'The protected runtime is already bound to a different Windows owner SID.' }
    } else {
        $stream = [IO.File]::Open($script:OwnerSidPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $bytes = [Text.Encoding]::ASCII.GetBytes($ownerSid + "`r`n")
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        } finally { $stream.Dispose() }
        Assert-NoReparseChain $script:OwnerSidPath
        Assert-SafeCloneAcl $script:OwnerSidPath
    }

    $sourceHashes = @{}
    foreach ($row in @(@{ source = $script:WorkerStaged; destination = $script:WorkerInstalled }, @{ source = $script:VssStaged; destination = $script:VssInstalled })) {
        Assert-NoReparseChain $row.source
        if ([IO.File]::Exists($row.destination)) {
            Assert-NoReparseChain $row.destination
            Assert-SafeCloneAcl $row.destination
        }
        $sourceHashes[$row.destination] = (Get-FileHash -LiteralPath $row.source -Algorithm SHA256).Hash
        [IO.File]::Copy($row.source, $row.destination, $true)
        Assert-NoReparseChain $row.destination
        $installedHash = (Get-FileHash -LiteralPath $row.destination -Algorithm SHA256).Hash
        if ($installedHash -ne $sourceHashes[$row.destination]) { throw "Installed bytes differ from the signed release artifact: $($row.destination)" }
        Assert-ReleaseSignature $row.destination
        Assert-SafeCloneAcl $row.destination
    }

    # Reconfirm the exact state/runtime DACLs after installation. The one-file
    # bundle extracts only beneath this locked runtime Temp directory.
    foreach ($directory in @($script:AppRoot, $script:RuntimeRoot, $script:RuntimeTemp, $script:StateRoot)) {
        Assert-NoReparseChain $directory
        Assert-SafeCloneAcl $directory -RequireProtected
    }
    $record = [ordered]@{
        schema = 1
        installed_at_utc = [DateTime]::UtcNow.ToString('o')
        owner_sid = $ownerSid
        worker_sha256 = (Get-FileHash -LiteralPath $script:WorkerInstalled -Algorithm SHA256).Hash
        vss_helper_sha256 = (Get-FileHash -LiteralPath $script:VssInstalled -Algorithm SHA256).Hash
        worker_signer = (Get-SignerThumbprint $script:WorkerInstalled)
        vss_helper_signer = (Get-SignerThumbprint $script:VssInstalled)
        runtime = $script:RuntimeRoot
        state = $script:StateRoot
    }
    $audit = Join-Path $script:StateRoot 'runtime-install.json'
    [IO.File]::WriteAllText($audit, ($record | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
    Assert-NoReparseChain $audit
    Assert-SafeCloneAcl $audit
    Write-Output "Protected runtime installed: $script:WorkerInstalled"
    Write-Output "Native VSS helper installed: $script:VssInstalled"
    Write-Output "Protected state: $script:StateRoot"
}

function Invoke-SelfCheck {
    if ($script:WorkerInstalled -ne 'C:\ProgramData\L-vault\clone-runtime\LocalVaultCloneWorker.exe' -or
        $script:StateRoot -ne 'C:\ProgramData\L-vault\clone-state' -or
        $script:VssInstalled -ne 'C:\ProgramData\L-vault\clone-runtime\LVaultVssSnapshot.exe') {
        throw 'Fixed runtime contract changed.'
    }
    if ($script:BundleRoot -notlike 'E:\LocalVault\.build\clone-runtime-stage\bundle') {
        throw 'Build staging path changed.'
    }
    if ($script:RuntimeTemp -notlike ($script:RuntimeRoot + '\Temp')) { throw 'PyInstaller extraction path changed.' }
    $security = New-CloneDirectorySecurity
    if (-not $security.AreAccessRulesProtected) { throw 'The proposed runtime DACL is not protected.' }
    $rules = @($security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $masks = @{}
    foreach ($rule in $rules) {
        $masks[$rule.IdentityReference.Value] = [long]$masks[$rule.IdentityReference.Value] -bor [long]$rule.FileSystemRights
    }
    foreach ($sid in @($script:SystemSid, $script:AdministratorsSid)) {
        if (([long]$masks[$sid] -band $script:FullControlMask) -ne $script:FullControlMask) {
            throw "The proposed DACL lacks full control for $sid."
        }
    }
    $ownerDenies = @($rules | Where-Object {
        $_.IdentityReference.Value -eq $script:OwnerRightsSid -and
        $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny
    })
    if ($ownerDenies.Count -ne 1 -or
        ([long]$ownerDenies[0].FileSystemRights -band 0x000C0000L) -ne 0x000C0000L) {
        throw 'The proposed DACL does not prevent the owner changing DACL/owner.'
    }
    if (([long]$masks[$script:UsersSid] -band $script:ReadExecuteMask) -ne $script:ReadExecuteMask -or
        ([long]$masks[$script:UsersSid] -band $script:UnsafeUserWriteMask) -ne 0) {
        throw 'The proposed DACL does not restrict Users to read/execute.'
    }
    Write-Output 'PASS fixed worker and VSS helper paths'
    Write-Output 'PASS fixed protected state path'
    Write-Output 'PASS build output is a repository-local development staging directory'
    Write-Output 'PASS installation requires pinned valid Authenticode signatures'
    Write-Output 'PASS BuildOnly refuses administrator execution'
    Write-Output 'PASS proposed DACL grants SYSTEM/Administrators full control and Users read/execute only'
    Assert-ProgramDataAncestors
    Write-Output 'PASS standard users cannot delete/replace C:\ProgramData ancestors'
}

$modeCount = [int]$BuildOnly.IsPresent + [int]$Install.IsPresent + [int]$SelfCheck.IsPresent
if ($modeCount -gt 1) {
    throw 'Choose exactly one of -BuildOnly, -Install, or -SelfCheck.'
}
if ($SelfCheck) { Invoke-SelfCheck; exit 0 }
if ($BuildOnly) { Invoke-BuildOnly; exit 0 }
if ($Install) { Install-CloneRuntime; exit 0 }
throw 'Choose -BuildOnly, -Install, or -SelfCheck.'
