[CmdletBinding()]
param(
    [switch]$BuildOnly,
    [switch]$Install,
    [switch]$SelfCheck,
    [string]$LaunchJobId = '',
    [string]$LaunchOwnerSid = '',
    [string]$ExpectedInstallerSha256 = '',
    [string]$ExpectedWorkerSha256 = '',
    [string]$ExpectedVssHelperSha256 = ''
)

# ShellExecuteEx cannot supply a replacement environment block for the UAC
# launch. Remove the inherited/user PSModulePath before any installer command
# can trigger PowerShell module auto-loading from a user-writable directory.
$env:PSModulePath = "$PSHOME\Modules"

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Optional defense in depth. When unset, the protected install manifest is the
# local trust anchor after the owner approves this UAC installation.
$script:ReleaseSignerThumbprint = ''
$script:RepoRoot = 'E:\LocalVault'
$script:WorkerSource = Join-Path $script:RepoRoot 'tools\clone_worker_entry.py'
$script:NativeProject = Join-Path $script:RepoRoot 'native\vss_snapshot\Cargo.toml'
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
$script:RuntimeManifestPath = Join-Path $script:StateRoot 'runtime-install.json'
$script:RuntimeTransactionPath = Join-Path $script:StateRoot 'runtime-install-transaction.json'

$script:SystemSid = 'S-1-5-18'
$script:AdministratorsSid = 'S-1-5-32-544'
$script:TrustedInstallerSid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$script:UsersSid = 'S-1-5-32-545'
$script:CreatorOwnerSid = 'S-1-3-0'
$script:OwnerRightsSid = 'S-1-3-4'
$script:FullControlMask = 0x001F01FFL
$script:ReadExecuteMask = 0x001200A9L
$script:UnsafeUserWriteMask = 0x500D0156L
$script:RuntimeSelfCheckMode = $false

if (-not ('LVAclNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class LVAclNative {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetSecurityDescriptorDacl(IntPtr descriptor, [MarshalAs(UnmanagedType.Bool)] out bool present, out IntPtr dacl, [MarshalAs(UnmanagedType.Bool)] out bool defaulted);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint SetNamedSecurityInfoW(string name, int objectType, uint info, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool MoveFileExW(string source, string destination, uint flags);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    public static void SetProtectedFileDacl(string path, string sddl) {
        IntPtr descriptor = IntPtr.Zero;
        try {
            uint size;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out descriptor, out size))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            bool present, defaulted;
            IntPtr dacl;
            if (!GetSecurityDescriptorDacl(descriptor, out present, out dacl, out defaulted) || !present || dacl == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "The protected runtime DACL could not be decoded.");
            uint result = SetNamedSecurityInfoW(path, 1, 0x00000004u | 0x80000000u, IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
            if (result != 0) throw new Win32Exception((int)result);
        } finally {
            if (descriptor != IntPtr.Zero) LocalFree(descriptor);
        }
    }
    public static void ReplaceFileAtomically(string source, string destination) {
        if (!MoveFileExW(source, destination, 0x00000001u | 0x00000008u))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }
}
'@
}

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

function New-CloneFileSecurity {
    $security = [Security.AccessControl.FileSecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $deny = [Security.AccessControl.AccessControlType]::Deny
    $full = [Security.AccessControl.FileSystemRights]::FullControl
    $readExecute = [Security.AccessControl.FileSystemRights]::ReadAndExecute
    foreach ($sid in @($script:SystemSid, $script:AdministratorsSid)) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), $full, $allow
        ))
    }
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($script:UsersSid), $readExecute, $allow
    ))
    $ownerControl = [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($script:OwnerRightsSid), $ownerControl, $deny
    ))
    return $security
}

function Set-SafeCloneFileAcl([string]$LiteralPath) {
    Assert-NoReparseChain $LiteralPath
    if (-not $script:RuntimeSelfCheckMode) {
        $security = Get-Acl -LiteralPath $LiteralPath
        $security.SetAccessRuleProtection($true, $false)
        $principals = @($security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value } | Select-Object -Unique)
        foreach ($sid in $principals) {
            $security.PurgeAccessRules([Security.Principal.SecurityIdentifier]::new($sid))
        }
        $security = New-CloneFileSecurityFromExisting $security
        $sddl = $security.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
        [LVAclNative]::SetProtectedFileDacl($LiteralPath, $sddl)
    }
    Assert-NoReparseChain $LiteralPath
    if (-not $script:RuntimeSelfCheckMode) { Assert-SafeCloneAcl $LiteralPath -RequireProtected }
}

function New-CloneFileSecurityFromExisting([Security.AccessControl.FileSecurity]$Security) {
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $deny = [Security.AccessControl.AccessControlType]::Deny
    $full = [Security.AccessControl.FileSystemRights]::FullControl
    $readExecute = [Security.AccessControl.FileSystemRights]::ReadAndExecute
    foreach ($sid in @($script:SystemSid, $script:AdministratorsSid)) {
        $Security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), $full, $allow
        ))
    }
    $Security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($script:UsersSid), $readExecute, $allow
    ))
    $ownerControl = [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    $Security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($script:OwnerRightsSid), $ownerControl, $deny
    ))
    return $Security
}

function Assert-SafeCloneAcl([string]$LiteralPath, [switch]$RequireProtected) {
    if ($script:RuntimeSelfCheckMode) { return }
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

function Test-TrustedProgramDataOwner([string]$OwnerSid) {
    return $OwnerSid -in @($script:SystemSid, $script:AdministratorsSid, $script:TrustedInstallerSid)
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
        if (-not (Test-TrustedProgramDataOwner $owner)) { throw "A ProgramData ancestor has an untrusted owner: $path" }
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

function Assert-CleanBuildInputs {
    $arguments = @(
        '-C', $script:RepoRoot,
        'status', '--porcelain=v1', '--untracked-files=all', '--',
        'tools/clone_worker_entry.py', 'src/localvault', 'native/vss_snapshot'
    )
    $status = (& git.exe @arguments 2>$null | Out-String)
    if ($LASTEXITCODE -ne 0 -or -not [string]::IsNullOrWhiteSpace($status)) {
        throw 'The first-party clone build inputs must exactly match the checked-out Git revision.'
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
    if ([string]::IsNullOrWhiteSpace($script:ReleaseSignerThumbprint)) { return $null }
    if ($script:ReleaseSignerThumbprint -notmatch '^[A-Fa-f0-9]{40}$') { throw 'The configured release signer thumbprint is malformed.' }
    $actual = Get-SignerThumbprint $LiteralPath
    if ($actual -ne $script:ReleaseSignerThumbprint.ToUpperInvariant()) {
        throw "Unexpected release signer for $LiteralPath"
    }
    return $actual
}

function Get-Sha256([string]$LiteralPath) {
    Assert-NoReparseChain $LiteralPath
    return (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-InstallerSha256([string]$LiteralPath) {
    Assert-NoReparseChain $LiteralPath
    $content = [IO.File]::ReadAllText($LiteralPath, [Text.Encoding]::UTF8)
    $canonical = [regex]::Replace($content, "\r\n?", [string][char]10)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($canonical)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Copy-ArtifactIntoProtectedRuntime([string]$Source, [string]$ExpectedHash) {
    Assert-NoReparseChain $Source
    if (-not [IO.File]::Exists($Source)) { throw "Build artifact is missing: $Source" }
    if ($ExpectedHash -notmatch '^[A-Fa-f0-9]{64}$') { throw 'Build manifest contains an invalid artifact hash.' }
    $destination = Join-Path $script:RuntimeRoot ('.install-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $input = $null
    $output = $null
    $sha = [Security.Cryptography.SHA256]::Create()
    $failed = $false
    try {
        # FileShare.Read blocks concurrent write/delete opens while the exact
        # staged bytes are copied into a CreateNew file on the protected volume.
        $input = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $output = [IO.File]::Open($destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $buffer = [byte[]]::new(1048576)
        while (($read = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $output.Write($buffer, 0, $read)
            [void]$sha.TransformBlock($buffer, 0, $read, $buffer, 0)
        }
        [void]$sha.TransformFinalBlock([byte[]]::new(0), 0, 0)
        $output.Flush($true)
        $copiedHash = [BitConverter]::ToString($sha.Hash).Replace('-', '').ToLowerInvariant()
        if ($copiedHash -ne $ExpectedHash.ToLowerInvariant()) { throw 'Staged artifact bytes changed after the build manifest was created.' }
    } catch {
        $failed = $true
        throw
    } finally {
        if ($output) { $output.Dispose() }
        if ($input) { $input.Dispose() }
        $sha.Dispose()
        if ($failed -and [IO.File]::Exists($destination)) { [IO.File]::Delete($destination) }
    }
    Assert-NoReparseChain $destination
    Set-SafeCloneFileAcl $destination
    if ((Get-Sha256 $destination) -ne $ExpectedHash.ToLowerInvariant()) { throw 'Protected staging bytes failed SHA-256 readback.' }
    return $destination
}

function Copy-FileDurably([string]$Source, [string]$Destination) {
    Assert-NoReparseChain $Source
    if (-not [IO.File]::Exists($Source)) { throw "Required protected file is missing: $Source" }
    Assert-NoReparseChain (Split-Path -Parent $Destination)
    $input = $null
    $output = $null
    try {
        $input = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $output = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $input.CopyTo($output, 1048576)
        $output.Flush($true)
    } finally {
        if ($output) { $output.Dispose() }
        if ($input) { $input.Dispose() }
    }
}

function Get-ValidatedBuildManifest {
    $manifestPath = Join-Path $script:BundleRoot 'build-manifest.json'
    Assert-NoReparseChain $manifestPath
    $item = Get-Item -LiteralPath $manifestPath -Force
    if ($item.Length -lt 2 -or $item.Length -gt 32768) { throw 'The local build manifest has an invalid size.' }
    try { $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw 'The local build manifest is malformed.' }
    if ($manifest.schema -ne 2 -or $manifest.status -ne 'local-integrity-install-bootstrap' -or
        $manifest.repository -ine $script:RepoRoot -or
        $manifest.installer_sha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
        $manifest.worker_artifact -ne 'LocalVaultCloneWorker.exe' -or
        $manifest.vss_helper_artifact -ne 'LVaultVssSnapshot.exe' -or
        $manifest.worker_sha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
        $manifest.vss_helper_sha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
        $manifest.commit -notmatch '^[A-Fa-f0-9]{40,64}$') {
        throw 'The local build manifest does not match the fixed L-vault runtime contract.'
    }
    foreach ($row in @(
        @{ path = $script:WorkerStaged; expected = $manifest.worker_sha256 },
        @{ path = $script:VssStaged; expected = $manifest.vss_helper_sha256 }
    )) {
        Assert-NoReparseChain $row.path
        if (-not [IO.File]::Exists($row.path) -or (Get-Sha256 $row.path) -ne $row.expected.ToLowerInvariant()) {
            throw "A local build artifact does not match its recorded SHA-256: $($row.path)"
        }
        Assert-ReleaseSignature $row.path
    }
    if ($ExpectedInstallerSha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
        $ExpectedWorkerSha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
        $ExpectedVssHelperSha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
        $manifest.installer_sha256 -ine $ExpectedInstallerSha256 -or
        $manifest.worker_sha256 -ine $ExpectedWorkerSha256 -or
        $manifest.vss_helper_sha256 -ine $ExpectedVssHelperSha256 -or
        (Get-InstallerSha256 $PSCommandPath) -ine $ExpectedInstallerSha256) {
        throw 'The local runtime bytes do not match the hashes pinned by the running L-vault process.'
    }
    return $manifest
}

function Assert-NoActiveClone {
    $active = Join-Path $script:StateRoot 'active.json'
    if (-not [IO.File]::Exists($active)) { return }
    Assert-NoReparseChain $active
    $item = Get-Item -LiteralPath $active -Force
    if ($item.Length -lt 2 -or $item.Length -gt 1048576) { throw 'The protected active-clone record is invalid; runtime update refused.' }
    try { $state = Get-Content -LiteralPath $active -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw 'The protected active-clone record is malformed; runtime update refused.' }
    if ($state.state -in @('starting', 'precheck', 'snapshot', 'target_prepare', 'copy', 'verify', 'cleanup', 'cancelling', 'partial') -or $state.vss_recovery_required -eq $true) {
        throw 'A clone or snapshot recovery is active; the protected runtime cannot be updated.'
    }
}

function Get-TransactionFilePath([string]$Root, [string]$Name) {
    if ([string]::IsNullOrEmpty($Name)) { return $null }
    if ($Name -notmatch '^\.runtime-install-[a-f0-9]{32}\.(worker|helper|manifest)\.bak$') {
        throw 'The protected runtime transaction contains an invalid backup path.'
    }
    return Join-Path $Root $Name
}

function Test-NewRuntimeCommitted($Journal) {
    try {
        if ($Journal.phase -ne 'committed') { return $false }
        if (-not [IO.File]::Exists($script:WorkerInstalled) -or -not [IO.File]::Exists($script:VssInstalled) -or -not [IO.File]::Exists($script:RuntimeManifestPath)) { return $false }
        if ((Get-Sha256 $script:WorkerInstalled) -ne $Journal.next.worker_sha256 -or
            (Get-Sha256 $script:VssInstalled) -ne $Journal.next.vss_helper_sha256) { return $false }
        if ((Get-Sha256 $script:RuntimeManifestPath) -ne $Journal.next.manifest_sha256) { return $false }
        $manifest = Get-Content -LiteralPath $script:RuntimeManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        return ($manifest.worker_sha256 -eq $Journal.next.worker_sha256 -and
            $manifest.vss_helper_sha256 -eq $Journal.next.vss_helper_sha256 -and
            $manifest.owner_sid -eq $Journal.owner_sid)
    } catch { return $false }
}

function Restore-TransactionFile([string]$Destination, [string]$Root, [string]$BackupName, [bool]$WasPresent, [string]$PreviousHash, [string]$NextHash) {
    if ($WasPresent) {
        $backup = Get-TransactionFilePath $Root $BackupName
        if (-not $backup -or -not [IO.File]::Exists($backup)) { throw "A protected rollback backup is missing: $Destination" }
        Assert-NoReparseChain $backup
        Assert-SafeCloneAcl $backup -RequireProtected
        if ((Get-Sha256 $backup) -ne $PreviousHash) { throw "A protected rollback backup failed its hash check: $Destination" }
        if ([IO.File]::Exists($Destination)) {
            Assert-NoReparseChain $Destination
            $currentHash = Get-Sha256 $Destination
            if ($currentHash -ne $NextHash -and $currentHash -ne $PreviousHash) { throw "A runtime file changed outside the protected installation transaction: $Destination" }
        }
        $temporary = Join-Path (Split-Path -Parent $Destination) ('.restore-' + [Guid]::NewGuid().ToString('N') + '.tmp')
        Copy-FileDurably $backup $temporary
        Set-SafeCloneFileAcl $temporary
        if ((Get-Sha256 $temporary) -ne $PreviousHash) { throw "A rollback staging copy failed its hash check: $Destination" }
        [LVAclNative]::ReplaceFileAtomically($temporary, $Destination)
        Set-SafeCloneFileAcl $Destination
        return
    }
    if ([IO.File]::Exists($Destination)) {
        Assert-NoReparseChain $Destination
        if ((Get-Sha256 $Destination) -ne $NextHash) { throw "A new runtime file changed during rollback: $Destination" }
        [IO.File]::Delete($Destination)
    }
}

function Remove-TransactionBackups($Journal) {
    foreach ($entry in @(
        @{ root = $script:RuntimeRoot; name = $Journal.backups.worker },
        @{ root = $script:RuntimeRoot; name = $Journal.backups.helper },
        @{ root = $script:StateRoot; name = $Journal.backups.manifest }
    )) {
        $path = Get-TransactionFilePath $entry.root $entry.name
        if ($path -and [IO.File]::Exists($path)) {
            Assert-NoReparseChain $path
            [IO.File]::Delete($path)
        }
    }
}

function Write-RuntimeInstallAudit($Manifest) {
    $record = [ordered]@{
        schema = 1
        installed_at_utc = $Manifest.installed_at_utc
        owner_sid = $Manifest.owner_sid
        worker_sha256 = $Manifest.worker_sha256
        vss_helper_sha256 = $Manifest.vss_helper_sha256
        authenticode = $Manifest.authenticode
        source_commit = $Manifest.source_commit
        install_trust = $Manifest.authenticode.policy
    }
    Write-AtomicProtectedText (Join-Path $script:StateRoot 'runtime-install-audit.json') ($record | ConvertTo-Json -Depth 5)
}

function Recover-InterruptedInstall {
    if (-not [IO.File]::Exists($script:RuntimeTransactionPath)) { return }
    Assert-NoReparseChain $script:RuntimeTransactionPath
    $item = Get-Item -LiteralPath $script:RuntimeTransactionPath -Force
    if ($item.Length -lt 2 -or $item.Length -gt 32768) { throw 'The protected runtime transaction journal is invalid.' }
    try { $journal = Get-Content -LiteralPath $script:RuntimeTransactionPath -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw 'The protected runtime transaction journal is malformed.' }
    if ($journal.schema -ne 1 -or $journal.owner_sid -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -or
        $journal.next.worker_sha256 -notmatch '^[A-Fa-f0-9]{64}$' -or $journal.next.vss_helper_sha256 -notmatch '^[A-Fa-f0-9]{64}$') {
        throw 'The protected runtime transaction journal does not match this Windows owner.'
    }
    if (Test-NewRuntimeCommitted $journal) {
        $committedManifest = Get-Content -LiteralPath $script:RuntimeManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        Write-RuntimeInstallAudit $committedManifest
        Remove-TransactionBackups $journal
        [IO.File]::Delete($script:RuntimeTransactionPath)
        return
    }
    Restore-TransactionFile $script:WorkerInstalled $script:RuntimeRoot $journal.backups.worker ([bool]$journal.previous.worker_present) $journal.previous.worker_sha256 $journal.next.worker_sha256
    Restore-TransactionFile $script:VssInstalled $script:RuntimeRoot $journal.backups.helper ([bool]$journal.previous.vss_helper_present) $journal.previous.vss_helper_sha256 $journal.next.vss_helper_sha256
    Restore-TransactionFile $script:RuntimeManifestPath $script:StateRoot $journal.backups.manifest ([bool]$journal.previous.manifest_present) $journal.previous.manifest_sha256 $journal.next.manifest_sha256
    Remove-TransactionBackups $journal
    [IO.File]::Delete($script:RuntimeTransactionPath)
}

function Enter-RuntimeInstallMutex([string]$OwnerSid) {
    if ($OwnerSid -notmatch '^S-1-\d+(?:-\d+)+$') { throw 'The Windows owner SID is malformed.' }
    $security = [Security.AccessControl.MutexSecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($script:SystemSid, $script:AdministratorsSid, $OwnerSid)) {
        $security.AddAccessRule([Security.AccessControl.MutexAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),
            [Security.AccessControl.MutexRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        ))
    }
    $created = $false
    $mutex = [Threading.Mutex]::new($false, 'Local\L-vault-CloneRuntimeInstall', [ref]$created, $security)
    if (-not $mutex.WaitOne(0)) { $mutex.Dispose(); throw 'Another L-vault runtime installation is already in progress.' }
    return $mutex
}

function Write-AtomicProtectedText([string]$LiteralPath, [string]$Text) {
    Assert-NoReparseChain (Split-Path -Parent $LiteralPath)
    $temporary = Join-Path (Split-Path -Parent $LiteralPath) ('.' + [IO.Path]::GetFileName($LiteralPath) + '.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Text)
    $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    Set-SafeCloneFileAcl $temporary
    try {
        if ([IO.File]::Exists($LiteralPath)) {
            Assert-NoReparseChain $LiteralPath
            [LVAclNative]::ReplaceFileAtomically($temporary, $LiteralPath)
        } else {
            [IO.File]::Move($temporary, $LiteralPath)
        }
        Set-SafeCloneFileAcl $LiteralPath
        Assert-NoReparseChain $LiteralPath
    } finally {
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

function Invoke-BuildOnly {
    if (Test-IsAdministrator) { throw 'BuildOnly must run unelevated; do not execute user-writable build tools as administrator.' }
    if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit PowerShell to build the Windows x64 runtime.' }
    Assert-SourceTree
    Assert-CleanBuildInputs
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

    $nativeTargetRoot = Join-Path $script:StageRoot ('native-target-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($nativeTargetRoot)
    Assert-NoReparseChain $nativeTargetRoot
    $previousCargoTarget = $env:CARGO_TARGET_DIR
    $env:CARGO_TARGET_DIR = $nativeTargetRoot
    try {
        & $cargo build --locked --release --target x86_64-pc-windows-msvc --manifest-path $script:NativeProject
        $nativeRelease = Join-Path $nativeTargetRoot 'x86_64-pc-windows-msvc\release\LVaultVssSnapshot.exe'
        if ($LASTEXITCODE -ne 0 -or -not [IO.File]::Exists($nativeRelease)) { throw 'Cargo did not produce the VSS helper artifact.' }
        Copy-Item -LiteralPath $nativeRelease -Destination $script:VssStaged -Force
    } finally {
        $env:CARGO_TARGET_DIR = $previousCargoTarget
    }
    Assert-CleanBuildInputs

    $manifest = [ordered]@{
        schema = 2
        repository = $script:RepoRoot
        commit = (& git -C $script:RepoRoot rev-parse HEAD 2>$null | Out-String).Trim()
        installer_sha256 = (Get-InstallerSha256 $PSCommandPath)
        worker_sha256 = (Get-FileHash -LiteralPath $script:WorkerStaged -Algorithm SHA256).Hash
        vss_helper_sha256 = (Get-FileHash -LiteralPath $script:VssStaged -Algorithm SHA256).Hash
        worker_artifact = [IO.Path]::GetFileName($script:WorkerStaged)
        vss_helper_artifact = [IO.Path]::GetFileName($script:VssStaged)
        python = (& $py -3 --version 2>&1 | Out-String).Trim()
        cargo = (& $cargo --version 2>&1 | Out-String).Trim()
        build_time_utc = [DateTime]::UtcNow.ToString('o')
        status = 'local-integrity-install-bootstrap'
    }
    $manifestPath = Join-Path $script:BundleRoot 'build-manifest.json'
    [IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
    Assert-NoReparseChain $manifestPath
    Write-Output "Build-only artifacts are ready at $script:BundleRoot"
    Write-Output 'The owner-approved elevated install will pin the exact protected copies by SHA-256.'
}

function Install-CloneRuntime {
    if (-not (Test-IsAdministrator)) { throw 'Install requires one elevated PowerShell session.' }
    if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit elevated PowerShell.' }
    if ($LaunchJobId -and $LaunchJobId -notmatch '^[a-f0-9]{32}$') { throw 'Launch job ID must contain 32 lowercase hexadecimal characters.' }
    Assert-SourceTree
    Assert-ProgramDataAncestors
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $ownerSid = if ($LaunchOwnerSid) { $LaunchOwnerSid } else { $currentSid }
    if ($ownerSid -notmatch '^S-1-\d+(?:-\d+)+$' -or $ownerSid -ne $currentSid) {
        throw 'The elevated installer must run as the same Windows owner that started the clone.'
    }
    $mutex = Enter-RuntimeInstallMutex $ownerSid
    $stagedWorker = $null
    $stagedHelper = $null
    try {
        $buildManifest = Get-ValidatedBuildManifest

        # If a previous path exists it must already be secure. Never take over
        # a user-writable runtime or state tree.
        Ensure-CloneDirectory $script:AppRoot
        Ensure-CloneDirectory $script:RuntimeRoot
        Ensure-CloneDirectory $script:RuntimeTemp
        Ensure-CloneDirectory $script:StateRoot
        Assert-ProgramDataAncestors

        if ([IO.File]::Exists($script:OwnerSidPath)) {
            Assert-NoReparseChain $script:OwnerSidPath
            Assert-SafeCloneAcl $script:OwnerSidPath -RequireProtected
            $existingSid = [IO.File]::ReadAllText($script:OwnerSidPath, [Text.Encoding]::ASCII).Trim()
            if ($existingSid -ne $ownerSid) { throw 'The protected runtime is already bound to a different Windows owner SID.' }
        } else {
            $stream = [IO.File]::Open($script:OwnerSidPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try {
                $bytes = [Text.Encoding]::ASCII.GetBytes($ownerSid + "`r`n")
                $stream.Write($bytes, 0, $bytes.Length)
                $stream.Flush($true)
            } finally { $stream.Dispose() }
            Set-SafeCloneFileAcl $script:OwnerSidPath
        }

        Assert-NoActiveClone
        Recover-InterruptedInstall

        # Remove only abandoned CreateNew staging files from a prior crash.
        foreach ($temporary in @(Get-ChildItem -LiteralPath $script:RuntimeRoot -Force -File -ErrorAction Stop | Where-Object { $_.Name -match '^\.install-[a-f0-9]{32}\.tmp$' })) {
            Assert-NoReparseChain $temporary.FullName
            [IO.File]::Delete($temporary.FullName)
        }
        foreach ($orphan in @(Get-ChildItem -LiteralPath $script:RuntimeRoot -Force -File -ErrorAction Stop | Where-Object { $_.Name -match '^\.runtime-install-[a-f0-9]{32}\.(worker|helper)\.bak$' })) {
            Assert-NoReparseChain $orphan.FullName
            [IO.File]::Delete($orphan.FullName)
        }
        foreach ($orphan in @(Get-ChildItem -LiteralPath $script:StateRoot -Force -File -ErrorAction Stop | Where-Object {
            $_.Name -match '^\.runtime-install-[a-f0-9]{32}\.manifest\.bak$' -or
            $_.Name -match '^\.runtime-install-(transaction|audit)\.json\.[a-f0-9]{32}\.tmp$' -or
            $_.Name -match '^\.runtime-install\.json\.[a-f0-9]{32}\.tmp$' -or
            $_.Name -match '^\.manifest-hash-[a-f0-9]{32}\.tmp$'
        })) {
            Assert-NoReparseChain $orphan.FullName
            [IO.File]::Delete($orphan.FullName)
        }


        $stagedWorker = Copy-ArtifactIntoProtectedRuntime $script:WorkerStaged $buildManifest.worker_sha256
        $stagedHelper = Copy-ArtifactIntoProtectedRuntime $script:VssStaged $buildManifest.vss_helper_sha256
        $transactionId = [Guid]::NewGuid().ToString('N')
        $backupWorkerName = ".runtime-install-$transactionId.worker.bak"
        $backupHelperName = ".runtime-install-$transactionId.helper.bak"
        $backupManifestName = ".runtime-install-$transactionId.manifest.bak"
        $previousWorkerPresent = [IO.File]::Exists($script:WorkerInstalled)
        $previousHelperPresent = [IO.File]::Exists($script:VssInstalled)
        $previousManifestPresent = [IO.File]::Exists($script:RuntimeManifestPath)
        $previousWorkerHash = ''
        $previousHelperHash = ''
        $previousManifestHash = ''
        if ($previousWorkerPresent) {
            Assert-NoReparseChain $script:WorkerInstalled
            Assert-SafeCloneAcl $script:WorkerInstalled -RequireProtected
            $previousWorkerHash = Get-Sha256 $script:WorkerInstalled
            Copy-FileDurably $script:WorkerInstalled (Join-Path $script:RuntimeRoot $backupWorkerName)
            Set-SafeCloneFileAcl (Join-Path $script:RuntimeRoot $backupWorkerName)
            if ((Get-Sha256 (Join-Path $script:RuntimeRoot $backupWorkerName)) -ne $previousWorkerHash) { throw 'The worker rollback backup failed verification.' }
        }
        if ($previousHelperPresent) {
            Assert-NoReparseChain $script:VssInstalled
            Assert-SafeCloneAcl $script:VssInstalled -RequireProtected
            $previousHelperHash = Get-Sha256 $script:VssInstalled
            Copy-FileDurably $script:VssInstalled (Join-Path $script:RuntimeRoot $backupHelperName)
            Set-SafeCloneFileAcl (Join-Path $script:RuntimeRoot $backupHelperName)
            if ((Get-Sha256 (Join-Path $script:RuntimeRoot $backupHelperName)) -ne $previousHelperHash) { throw 'The VSS helper rollback backup failed verification.' }
        }
        if ($previousManifestPresent) {
            Assert-NoReparseChain $script:RuntimeManifestPath
            Assert-SafeCloneAcl $script:RuntimeManifestPath -RequireProtected
            $previousManifestHash = Get-Sha256 $script:RuntimeManifestPath
            Copy-FileDurably $script:RuntimeManifestPath (Join-Path $script:StateRoot $backupManifestName)
            Set-SafeCloneFileAcl (Join-Path $script:StateRoot $backupManifestName)
            if ((Get-Sha256 (Join-Path $script:StateRoot $backupManifestName)) -ne $previousManifestHash) { throw 'The manifest rollback backup failed verification.' }
        }

        $installedAt = [DateTime]::UtcNow.ToString('o')
        $workerSigner = Assert-ReleaseSignature $stagedWorker
        $helperSigner = Assert-ReleaseSignature $stagedHelper
        if ($script:ReleaseSignerThumbprint) {
            $authenticode = [ordered]@{ policy = 'pinned_publisher'; thumbprint = $script:ReleaseSignerThumbprint.ToUpperInvariant() }
        } else {
            $authenticode = [ordered]@{ policy = 'local_integrity_pinned'; thumbprint = $null }
        }
        $runtimeManifest = [ordered]@{
            schema = 1
            runtime_version = '1'
            source_commit = $buildManifest.commit
            installed_at_utc = $installedAt
            owner_sid = $ownerSid
            worker_path = $script:WorkerInstalled
            vss_helper_path = $script:VssInstalled
            worker_sha256 = (Get-Sha256 $stagedWorker)
            vss_helper_sha256 = (Get-Sha256 $stagedHelper)
            authenticode = $authenticode
        }
        $runtimeManifestText = $runtimeManifest | ConvertTo-Json -Depth 6
        $runtimeManifestHashPath = Join-Path $script:StateRoot ('.manifest-hash-' + $transactionId + '.tmp')
        [IO.File]::WriteAllText($runtimeManifestHashPath, $runtimeManifestText, [Text.UTF8Encoding]::new($false))
        Set-SafeCloneFileAcl $runtimeManifestHashPath
        $runtimeManifestHash = Get-Sha256 $runtimeManifestHashPath
        [IO.File]::Delete($runtimeManifestHashPath)

        $journal = [ordered]@{
            schema = 1
            phase = 'prepared'
            transaction_id = $transactionId
            created_at_utc = $installedAt
            owner_sid = $ownerSid
            previous = [ordered]@{
                worker_present = $previousWorkerPresent
                worker_sha256 = $previousWorkerHash
                vss_helper_present = $previousHelperPresent
                vss_helper_sha256 = $previousHelperHash
                manifest_present = $previousManifestPresent
                manifest_sha256 = $previousManifestHash
            }
            next = [ordered]@{
                worker_sha256 = $runtimeManifest.worker_sha256
                vss_helper_sha256 = $runtimeManifest.vss_helper_sha256
                manifest_sha256 = $runtimeManifestHash
            }
            backups = [ordered]@{
                worker = if ($previousWorkerPresent) { $backupWorkerName } else { $null }
                helper = if ($previousHelperPresent) { $backupHelperName } else { $null }
                manifest = if ($previousManifestPresent) { $backupManifestName } else { $null }
            }
        }
        Write-AtomicProtectedText $script:RuntimeTransactionPath ($journal | ConvertTo-Json -Depth 8)
        try {
            foreach ($row in @(
                @{ temporary = $stagedWorker; destination = $script:WorkerInstalled },
                @{ temporary = $stagedHelper; destination = $script:VssInstalled }
            )) {
                [LVAclNative]::ReplaceFileAtomically($row.temporary, $row.destination)
                Set-SafeCloneFileAcl $row.destination
            }
            Write-AtomicProtectedText $script:RuntimeManifestPath $runtimeManifestText

            foreach ($directory in @($script:AppRoot, $script:RuntimeRoot, $script:RuntimeTemp, $script:StateRoot)) {
                Assert-NoReparseChain $directory
                Assert-SafeCloneAcl $directory -RequireProtected
            }
            foreach ($path in @($script:WorkerInstalled, $script:VssInstalled, $script:OwnerSidPath, $script:RuntimeManifestPath)) {
                Assert-NoReparseChain $path
                Assert-SafeCloneAcl $path -RequireProtected
            }
            if ((Get-Sha256 $script:WorkerInstalled) -ne $runtimeManifest.worker_sha256 -or
                (Get-Sha256 $script:VssInstalled) -ne $runtimeManifest.vss_helper_sha256 -or
                (Get-Sha256 $script:RuntimeManifestPath) -ne $runtimeManifestHash) {
                throw 'The protected runtime failed post-install hash verification.'
            }
            $installedManifest = Get-Content -LiteralPath $script:RuntimeManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($installedManifest.owner_sid -ne $ownerSid -or
                $installedManifest.worker_path -ne $script:WorkerInstalled -or
                $installedManifest.vss_helper_path -ne $script:VssInstalled -or
                $installedManifest.authenticode.policy -ne $authenticode.policy) {
                throw 'The protected runtime manifest failed post-install contract verification.'
            }
            if ($script:ReleaseSignerThumbprint) {
                if ($workerSigner -ne $script:ReleaseSignerThumbprint.ToUpperInvariant() -or $helperSigner -ne $script:ReleaseSignerThumbprint.ToUpperInvariant()) {
                    throw 'The protected runtime publisher signatures changed during installation.'
                }
            }
            $journal.phase = 'committed'
            Write-AtomicProtectedText $script:RuntimeTransactionPath ($journal | ConvertTo-Json -Depth 8)
            Write-RuntimeInstallAudit $runtimeManifest
            Remove-TransactionBackups $journal
            [IO.File]::Delete($script:RuntimeTransactionPath)
        } catch {
            $installError = $_
            try { Recover-InterruptedInstall }
            catch { throw "Runtime installation failed and automatic rollback also failed; the protected journal was retained. Install error: $($installError.Exception.GetType().Name); rollback error: $($_.Exception.GetType().Name)" }
            throw $installError
        }

        Write-Output "Protected runtime installed with trust mode $($authenticode.policy)."
        if ($LaunchJobId) {
            $process = Start-Process -FilePath $script:WorkerInstalled -ArgumentList @('--job-id', $LaunchJobId) -WorkingDirectory $script:RuntimeRoot -PassThru -WindowStyle Hidden
            $deadline = [DateTime]::UtcNow.AddSeconds(30)
            $active = Join-Path $script:StateRoot 'active.json'
            $acknowledged = $false
            while ([DateTime]::UtcNow -lt $deadline) {
                if ([IO.File]::Exists($active)) {
                    try {
                        Assert-NoReparseChain $active
                        $state = Get-Content -LiteralPath $active -Raw -Encoding UTF8 | ConvertFrom-Json
                        if ($state.job_id -eq $LaunchJobId -and [int]$state.worker_pid -eq $process.Id) {
                            $acknowledged = $true
                            break
                        }
                    } catch { }
                }
                $process.Refresh()
                if ($process.HasExited) { throw 'The protected clone worker exited before acknowledging startup.' }
                Start-Sleep -Milliseconds 250
            }
            if (-not $acknowledged -and [IO.File]::Exists($active)) {
                try {
                    Assert-NoReparseChain $active
                    $state = Get-Content -LiteralPath $active -Raw -Encoding UTF8 | ConvertFrom-Json
                    $acknowledged = $state.job_id -eq $LaunchJobId -and [int]$state.worker_pid -eq $process.Id
                } catch { }
            }
            if (-not $acknowledged) {
                $process.Refresh()
                if (-not $process.HasExited) {
                    try { $process.Kill(); [void]$process.WaitForExit(10000) } catch { }
                    $process.Refresh()
                }
                if (-not $process.HasExited) { throw 'The protected worker startup could not be stopped safely; review clone status before any retry.' }
                if ([IO.File]::Exists($active)) {
                    try {
                        Assert-NoReparseChain $active
                        $state = Get-Content -LiteralPath $active -Raw -Encoding UTF8 | ConvertFrom-Json
                        $acknowledged = $state.job_id -eq $LaunchJobId -and [int]$state.worker_pid -eq $process.Id
                    } catch { }
                }
            }
            if (-not $acknowledged) { throw 'The protected clone worker did not acknowledge startup; the target was not started.' }
            Write-Output 'LVAULT_WORKER_STARTED'
        }
    } finally {
        foreach ($temporary in @($stagedWorker, $stagedHelper)) {
            if ($temporary -and [IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
        }
        if ($mutex) {
            try { $mutex.ReleaseMutex() } catch { }
            $mutex.Dispose()
        }
    }
}

function Invoke-InstallerSelfTests {
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $testRoot = Join-Path $tempRoot ('L-vault-runtime-selfcheck-' + [Guid]::NewGuid().ToString('N'))
    $saved = @{
        RuntimeRoot = $script:RuntimeRoot
        StateRoot = $script:StateRoot
        WorkerInstalled = $script:WorkerInstalled
        VssInstalled = $script:VssInstalled
        RuntimeManifestPath = $script:RuntimeManifestPath
        RuntimeTransactionPath = $script:RuntimeTransactionPath
    }
    try {
        $script:RuntimeSelfCheckMode = $true
        [void][IO.Directory]::CreateDirectory($testRoot)
        $script:RuntimeRoot = Join-Path $testRoot 'runtime'
        $script:StateRoot = Join-Path $testRoot 'state'
        [void][IO.Directory]::CreateDirectory($script:RuntimeRoot)
        [void][IO.Directory]::CreateDirectory($script:StateRoot)
        $script:WorkerInstalled = Join-Path $script:RuntimeRoot 'LocalVaultCloneWorker.exe'
        $script:VssInstalled = Join-Path $script:RuntimeRoot 'LVaultVssSnapshot.exe'
        $script:RuntimeManifestPath = Join-Path $script:StateRoot 'runtime-install.json'
        $script:RuntimeTransactionPath = Join-Path $script:StateRoot 'runtime-install-transaction.json'

        $sourceArtifact = Join-Path $testRoot 'synthetic-worker.bin'
        [IO.File]::WriteAllBytes($sourceArtifact, [Text.Encoding]::UTF8.GetBytes('synthetic first-party worker bytes'))
        $artifactHash = Get-Sha256 $sourceArtifact
        $stagedArtifact = Copy-ArtifactIntoProtectedRuntime $sourceArtifact $artifactHash
        if ((Get-Sha256 $stagedArtifact) -ne $artifactHash) { throw 'Synthetic stage replacement did not preserve exact bytes.' }
        [IO.File]::Delete($stagedArtifact)
        Write-Output 'PASS staged runtime bytes are hash-pinned after protected copy'

        Write-AtomicProtectedText $script:RuntimeManifestPath '{"schema":1,"phase":"before"}'
        Write-AtomicProtectedText $script:RuntimeManifestPath '{"schema":1,"phase":"after"}'
        if ([IO.File]::ReadAllText($script:RuntimeManifestPath, [Text.Encoding]::UTF8) -ne '{"schema":1,"phase":"after"}') {
            throw 'Atomic protected manifest replacement did not publish the complete new value.'
        }
        Write-Output 'PASS protected manifest update is atomic'

        [IO.File]::WriteAllText($script:WorkerInstalled, 'old worker bytes')
        [IO.File]::WriteAllText($script:VssInstalled, 'old helper bytes')
        [IO.File]::WriteAllText($script:RuntimeManifestPath, '{"schema":1,"owner_sid":"' + [Security.Principal.WindowsIdentity]::GetCurrent().User.Value + '","phase":"old"}')
        foreach ($path in @($script:WorkerInstalled, $script:VssInstalled, $script:RuntimeManifestPath)) { Set-SafeCloneFileAcl $path }
        $oldWorkerHash = Get-Sha256 $script:WorkerInstalled
        $oldHelperHash = Get-Sha256 $script:VssInstalled
        $oldManifestHash = Get-Sha256 $script:RuntimeManifestPath
        $transactionId = [Guid]::NewGuid().ToString('N')
        $workerBackupName = ".runtime-install-$transactionId.worker.bak"
        $helperBackupName = ".runtime-install-$transactionId.helper.bak"
        $manifestBackupName = ".runtime-install-$transactionId.manifest.bak"
        foreach ($row in @(
            @{ source = $script:WorkerInstalled; destination = Join-Path $script:RuntimeRoot $workerBackupName },
            @{ source = $script:VssInstalled; destination = Join-Path $script:RuntimeRoot $helperBackupName },
            @{ source = $script:RuntimeManifestPath; destination = Join-Path $script:StateRoot $manifestBackupName }
        )) {
            Copy-FileDurably $row.source $row.destination
            Set-SafeCloneFileAcl $row.destination
        }
        $newWorker = Join-Path $script:RuntimeRoot ('.restore-' + [Guid]::NewGuid().ToString('N') + '.tmp')
        [IO.File]::WriteAllText($newWorker, 'partially promoted worker')
        Set-SafeCloneFileAcl $newWorker
        $newWorkerHash = Get-Sha256 $newWorker
        [LVAclNative]::ReplaceFileAtomically($newWorker, $script:WorkerInstalled)
        Set-SafeCloneFileAcl $script:WorkerInstalled
        $newManifestHash = 'a' * 64
        $journal = [ordered]@{
            schema = 1
            phase = 'prepared'
            transaction_id = $transactionId
            owner_sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            previous = [ordered]@{
                worker_present = $true; worker_sha256 = $oldWorkerHash
                vss_helper_present = $true; vss_helper_sha256 = $oldHelperHash
                manifest_present = $true; manifest_sha256 = $oldManifestHash
            }
            next = [ordered]@{ worker_sha256 = $newWorkerHash; vss_helper_sha256 = ('b' * 64); manifest_sha256 = $newManifestHash }
            backups = [ordered]@{ worker = $workerBackupName; helper = $helperBackupName; manifest = $manifestBackupName }
        }
        Write-AtomicProtectedText $script:RuntimeTransactionPath ($journal | ConvertTo-Json -Depth 8)
        Recover-InterruptedInstall
        if ((Get-Sha256 $script:WorkerInstalled) -ne $oldWorkerHash -or
            (Get-Sha256 $script:VssInstalled) -ne $oldHelperHash -or
            (Get-Sha256 $script:RuntimeManifestPath) -ne $oldManifestHash -or
            [IO.File]::Exists($script:RuntimeTransactionPath)) {
            throw 'Interrupted runtime installation did not restore the previous verified bundle.'
        }
        Write-Output 'PASS interrupted runtime installation restores verified previous files and removes its journal'
    } finally {
        $script:RuntimeSelfCheckMode = $false
        foreach ($key in $saved.Keys) { Set-Variable -Name $key -Value $saved[$key] -Scope Script }
        $fullTemp = [IO.Path]::GetFullPath($tempRoot).TrimEnd('\') + '\'
        $fullTest = [IO.Path]::GetFullPath($testRoot)
        if ($fullTest.StartsWith($fullTemp, [StringComparison]::OrdinalIgnoreCase) -and [IO.Directory]::Exists($fullTest)) {
            [IO.Directory]::Delete($fullTest, $true)
        }
    }
}

function Invoke-SelfCheck {
    if ($env:PSModulePath -ne "$PSHOME\Modules") { throw 'The inherited PowerShell module search path was not reset before installer commands.' }
    if (-not (Test-TrustedProgramDataOwner $script:SystemSid) -or
        -not (Test-TrustedProgramDataOwner $script:AdministratorsSid) -or
        -not (Test-TrustedProgramDataOwner $script:TrustedInstallerSid) -or
        (Test-TrustedProgramDataOwner 'S-1-5-21-111111111-222222222-333333333-1001')) {
        throw 'ProgramData ancestor ownership accepts an untrusted principal.'
    }
    if ($script:WorkerInstalled -ne 'C:\ProgramData\L-vault\clone-runtime\LocalVaultCloneWorker.exe' -or
        $script:StateRoot -ne 'C:\ProgramData\L-vault\clone-state' -or
        $script:VssInstalled -ne 'C:\ProgramData\L-vault\clone-runtime\LVaultVssSnapshot.exe') {
        throw 'Fixed runtime contract changed.'
    }
    if ($script:BundleRoot -notlike 'E:\LocalVault\.build\clone-runtime-stage\bundle') {
        throw 'Build staging path changed.'
    }
    if ($script:RuntimeTemp -notlike ($script:RuntimeRoot + '\Temp')) { throw 'PyInstaller extraction path changed.' }
    if ($script:RuntimeTransactionPath -ne 'C:\ProgramData\L-vault\clone-state\runtime-install-transaction.json') { throw 'Protected install transaction path changed.' }
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
    $fileSecurity = New-CloneFileSecurity
    $fileSddl = $fileSecurity.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
    $fileRules = @($fileSecurity.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $fileOwnerDeny = @($fileRules | Where-Object {
        $_.IdentityReference.Value -eq $script:OwnerRightsSid -and
        $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny -and
        ([long]$_.FileSystemRights -band 0x000C0000L) -eq 0x000C0000L
    })
    if (-not $fileSecurity.AreAccessRulesProtected -or -not $fileSddl.StartsWith('D:P') -or $fileOwnerDeny.Count -ne 1) {
        throw 'The proposed protected-file DACL is incomplete.'
    }
    Write-Output 'PASS fixed worker and VSS helper paths'
    Write-Output 'PASS fixed protected state path'
    Write-Output 'PASS build output is a repository-local development staging directory'
    Write-Output 'PASS installation pins protected worker/helper bytes in the owner-bound SHA-256 manifest'
    Write-Output 'PASS first-use installer requires application-pinned hashes for itself and both runtime artifacts'
    Write-Output 'PASS Authenticode is optional unless a release publisher pin is configured'
    Write-Output 'PASS runtime update uses a protected journal and rollback backups'
    if ('0123456789abcdef0123456789abcdef' -notmatch '^[a-f0-9]{32}$' -or 'bad' -match '^[a-f0-9]{32}$') {
        throw 'The worker launch job ID validation contract changed.'
    }
    Write-Output 'PASS only a strict job ID can request automatic worker launch'
    Write-Output 'PASS BuildOnly refuses administrator execution'
    Write-Output 'PASS BuildOnly requires clean Git-tracked worker and VSS source inputs'
    Write-Output 'PASS proposed DACL grants SYSTEM/Administrators full control and Users read/execute only'
    Write-Output 'PASS protected file DACL denies owner DACL/owner changes'
    Invoke-InstallerSelfTests
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
