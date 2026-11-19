<#
.SYNOPSIS
    privscope collector - read-only Windows privilege-escalation audit fact collector.

.DESCRIPTION
    Gathers configuration FACTS relevant to local privilege-escalation hardening and writes
    them to a JSON document for offline analysis by the privscope analyzer.

    This script is READ-ONLY by design:
      * It queries CIM/WMI, the registry, scheduled-task definitions, and filesystem
        metadata + ACLs only.
      * It NEVER modifies the system: no writes, no service restarts, no probe writes to
        test writability.
      * It makes NO exploitation attempts and NO vulnerability judgments. It records raw
        ACLs plus the current principal's SIDs and leaves every writable-vs-not decision to
        the analyzer, so no privesc-shaped logic runs on the target.
      * It NEVER reads the contents of secret-bearing files (unattend passwords, autologon
        passwords, PowerShell history, etc.). For those it records only presence, path, and
        metadata so a human can review them.

    Every filesystem ACL is recorded once, in facts.acls, keyed by lower-cased path. Records
    elsewhere (services, tasks, autoruns, PATH entries) refer to paths only. Ancestor folders
    of every executable and PATH entry are recorded too, so the analyzer can reason about
    unquoted paths and missing folders without touching the host again.

    Everything that depends on the display language is read by SID or position, so the
    collector works the same on non-English Windows.

    Intended for auditing systems you own or are explicitly authorized to assess.

.PARAMETER OutFile
    Path to write the JSON collection document to. Defaults to
    .\privscope-<HOSTNAME>-<timestamp>.json in the current directory.

.PARAMETER Stdout
    Also emit the JSON document to standard output.

.NOTES
    Compatible with Windows PowerShell 5.1 and PowerShell 7+.
    privscope collector v0.1.0 - detect-and-report only.
#>
[CmdletBinding()]
param(
    [string]$OutFile,
    [switch]$Stdout
)

$ErrorActionPreference = 'Continue'
$script:AclTable = [ordered]@{}
$script:RegAclTable = [ordered]@{}

$IntegrityNames = @{
    'S-1-16-0'     = 'Untrusted'
    'S-1-16-4096'  = 'Low'
    'S-1-16-8192'  = 'Medium'
    'S-1-16-8448'  = 'Medium Plus'
    'S-1-16-12288' = 'High'
    'S-1-16-16384' = 'System'
    'S-1-16-20480' = 'Protected Process'
}

# --- ACL table ------------------------------------------------------------------------

# Raw discretionary ACL of one filesystem object. No writability judgment is made here.
function Get-AclFacts {
    param([string]$Path)
    $exists = $false
    try { $exists = Test-Path -LiteralPath $Path } catch { $exists = $false }
    if (-not $exists) {
        return [PSCustomObject]@{ path = $Path; exists = $false; aces = @() }
    }
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    } catch {
        return [PSCustomObject]@{ path = $Path; exists = $true; error = $_.Exception.Message; aces = @() }
    }
    $inheritOnlyFlag = [System.Security.AccessControl.PropagationFlags]::InheritOnly
    $aces = foreach ($ace in $acl.Access) {
        $sid = $null
        try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = $null }
        [PSCustomObject]@{
            identity     = $ace.IdentityReference.Value
            sid          = $sid
            rights       = $ace.FileSystemRights.ToString()
            access       = $ace.AccessControlType.ToString()
            inherited    = [bool]$ace.IsInherited
            inherit_only = (($ace.PropagationFlags -band $inheritOnlyFlag) -ne 0)
        }
    }
    [PSCustomObject]@{
        path   = $Path
        exists = $true
        owner  = $acl.Owner
        aces   = @($aces)
    }
}

function ConvertTo-AclKey {
    param([string]$Path)
    $k = $Path.Trim().Replace('/', '\').ToLowerInvariant()
    if ($k -match '^[a-z]:$') { return $k + '\' }
    if ($k.Length -gt 3 -and $k.EndsWith('\')) { $k = $k.TrimEnd('\') }
    return $k
}

function Test-RootedPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try { return [System.IO.Path]::IsPathRooted($Path) } catch { return $false }
}

function Add-AclFact {
    param([string]$Path)
    if (-not (Test-RootedPath $Path)) { return }
    $key = ConvertTo-AclKey $Path
    if ($script:AclTable.Contains($key)) { return }
    $script:AclTable[$key] = Get-AclFacts $Path
}

# Record a path and every folder above it (cached, so shared ancestors cost nothing).
function Add-AclFactWithAncestors {
    param([string]$Path)
    $p = $Path
    while (Test-RootedPath $p) {
        Add-AclFact $p
        $parent = $null
        try { $parent = Split-Path -Parent $p } catch { $parent = $null }
        if (-not $parent -or $parent -eq $p) { break }
        $p = $parent
    }
}

# --- registry-key ACLs ----------------------------------------------------------------
# A writable registry key is its own escalation path (set an execution hook, or redirect a
# service). Recorded as the raw DACL, keyed by a canonical "HKLM\..." path; the analyzer
# decides writability, same split as the filesystem table.

function ConvertTo-RegKey {
    param([string]$PsPath)
    $p = $PsPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
    $p = $p -replace '^HKEY_LOCAL_MACHINE', 'HKLM' -replace '^HKEY_CURRENT_USER', 'HKCU' -replace '^HKEY_USERS', 'HKU' -replace '^HKEY_CLASSES_ROOT', 'HKCR'
    $p = $p -replace '^HKLM:', 'HKLM' -replace '^HKCU:', 'HKCU' -replace '^HKU:', 'HKU' -replace '^HKCR:', 'HKCR'
    return $p
}

function Get-RegAclFacts {
    param([string]$PsPath)
    try {
        if (-not (Test-Path -LiteralPath $PsPath)) { return [PSCustomObject]@{ exists = $false; aces = @() } }
        $acl = Get-Acl -LiteralPath $PsPath -ErrorAction Stop
        $io = [System.Security.AccessControl.PropagationFlags]::InheritOnly
        $aces = foreach ($ace in $acl.Access) {
            $sid = $null
            try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = $null }
            [PSCustomObject]@{
                identity     = $ace.IdentityReference.Value
                sid          = $sid
                rights       = $ace.RegistryRights.ToString()
                access       = $ace.AccessControlType.ToString()
                inherited    = [bool]$ace.IsInherited
                inherit_only = (($ace.PropagationFlags -band $io) -ne 0)
            }
        }
        [PSCustomObject]@{ exists = $true; owner = $acl.Owner; aces = @($aces) }
    } catch {
        [PSCustomObject]@{ exists = $true; error = $_.Exception.Message; aces = @() }
    }
}

# Record a key's DACL and return its canonical path (for records to reference). Cached.
function Add-RegAcl {
    param([string]$PsPath)
    $key = ConvertTo-RegKey $PsPath
    $k = $key.ToLowerInvariant()
    if (-not $script:RegAclTable.Contains($k)) {
        $r = Get-RegAclFacts $PsPath
        $r | Add-Member -NotePropertyName path -NotePropertyValue $key -Force
        $script:RegAclTable[$k] = $r
    }
    return $key
}

# The fixed set of keys where write access alone is an escalation, plus the per-exe IFEO
# subkeys. Service keys are recorded from Get-ServiceFacts.
function Get-RegKeyFacts {
    $defs = @(
        @{ cat = 'ifeo';           path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' },
        @{ cat = 'appinit';        path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' },
        @{ cat = 'appcert';        path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' },
        @{ cat = 'winlogon';       path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' },
        @{ cat = 'lsa';            path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' },
        @{ cat = 'print_monitors'; path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' },
        @{ cat = 'netsh';          path = 'HKLM:\SOFTWARE\Microsoft\Netsh' },
        @{ cat = 'active_setup';   path = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components' },
        @{ cat = 'run';            path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
        @{ cat = 'run';            path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' },
        @{ cat = 'run';            path = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run' }
    )
    $out = @()
    foreach ($d in $defs) {
        $key = Add-RegAcl $d.path
        $out += [PSCustomObject]@{ category = $d.cat; key = $key; exists = [bool](Test-Path -LiteralPath $d.path) }
    }
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    if (Test-Path $ifeo) {
        Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
            $key = Add-RegAcl $_.PSPath
            $out += [PSCustomObject]@{ category = 'ifeo'; key = $key; exists = $true }
        }
    }
    $out
}

# --- path helpers ---------------------------------------------------------------------

# Executable path from a command line (facts only; whether an unquoted path with spaces is
# a problem is decided by the analyzer).
function Resolve-ImagePath {
    param([string]$PathName)
    if ([string]::IsNullOrWhiteSpace($PathName)) { return $null }
    $p = $PathName.Trim()
    if ($p.StartsWith('"')) {
        $end = $p.IndexOf('"', 1)
        if ($end -gt 1) { return $p.Substring(1, $end - 1) }
    }
    $m = [regex]::Match($p, '^(.*?\.exe)\b', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($p -split '\s+')[0]
}

function Expand-ImagePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $p = [Environment]::ExpandEnvironmentVariables($Path.Trim()).Trim('"')
    if ($p.StartsWith('\??\')) { $p = $p.Substring(4) }
    if ($p -like '\SystemRoot\*') { $p = $env:SystemRoot + $p.Substring(11) }
    return $p
}

# Resolve a registry-hook value (a DLL or exe reference) to a filesystem path. A bare module
# name resolves against System32 then the Windows dir; a command keeps only its program. The
# analyzer then checks that path's ACL, so unresolved/protected targets simply produce no
# finding. Kind is 'exe' or 'dll'.
function Resolve-HookModule {
    param([string]$Raw, [string]$Kind)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
    $p = Expand-ImagePath $Raw
    if (-not $p) { return $null }
    if ($Kind -eq 'exe') {
        $p = Resolve-ImagePath $p
        # drop switch-only / junk tokens that aren't a program path
        if ([string]::IsNullOrWhiteSpace($p)) { return $null }
        if ($p -notmatch '\\' -and $p -notmatch '^[\w.\-]+\.(exe|com|scr|bat|cmd|pif)$') { return $null }
    } else {
        $p = $p.Trim('"')
    }
    if ([string]::IsNullOrWhiteSpace($p)) { return $null }
    if (Test-RootedPath $p) { return $p }
    if ($p -match '^[\\/]') { return $null }          # not a real target (e.g. a bare switch)
    if ($p -notmatch '[\\/]') {
        if ($p -notmatch '\.[A-Za-z0-9_]+$') { $p = $p + $(if ($Kind -eq 'dll') { '.dll' } else { '.exe' }) }
        $c1 = Join-Path "$env:SystemRoot\System32" $p
        $c2 = Join-Path $env:SystemRoot $p
        if (Test-Path -LiteralPath $c1) { return $c1 }
        if (Test-Path -LiteralPath $c2) { return $c2 }
        return $null                                   # bare name resolves nowhere: leave unresolved
    }
    return $p
}

function Get-ParentDir {
    param([string]$Path)
    if (-not (Test-RootedPath $Path)) { return $null }
    try {
        $d = Split-Path -Parent $Path
        if ($d) { return $d }
    } catch {}
    return $null
}

# Account or group name -> SID, so rules never depend on localized names. Cached.
$script:SidCache = @{}
function ConvertTo-Sid {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    if ($Name -match '^S-1-[0-9-]+$') { return $Name }
    if ($Name -ieq 'LocalSystem') { return 'S-1-5-18' }
    if ($script:SidCache.ContainsKey($Name)) { return $script:SidCache[$Name] }
    $sid = $null
    try { $sid = ([System.Security.Principal.NTAccount]$Name).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = $null }
    $script:SidCache[$Name] = $sid
    return $sid
}

# whoami output read by column position, so localized headers don't matter.
function Get-WhoamiCsv {
    param([string]$Switch, [string[]]$Header)
    try { return @(& whoami.exe $Switch /fo csv /nh 2>$null | ConvertFrom-Csv -Header $Header) } catch { return @() }
}

# --- collectors -----------------------------------------------------------------------

function Get-PrincipalFacts {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $wp = New-Object System.Security.Principal.WindowsPrincipal($id)
    $isAdmin = $wp.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    # Enabled groups only: .NET leaves out deny-only groups (e.g. a UAC-filtered Administrators),
    # which is exactly the set that grants access.
    $groups = foreach ($grp in $id.Groups) {
        $name = $null
        try { $name = $grp.Translate([System.Security.Principal.NTAccount]).Value } catch { $name = $null }
        [PSCustomObject]@{ sid = $grp.Value; name = $name }
    }

    # whoami lists every token group, deny-only ones included. Used only to spot a
    # UAC-filtered admin and to read the integrity label, both by SID.
    $tokenSids = @(Get-WhoamiCsv '/groups' @('name', 'type', 'sid', 'attributes') | ForEach-Object { $_.sid })
    $label = $tokenSids | Where-Object { $_ -like 'S-1-16-*' } | Select-Object -First 1
    $integrity = $null
    if ($label) {
        $integrity = if ($IntegrityNames.ContainsKey($label)) { $IntegrityNames[$label] } else { $label }
    }

    $elevation = 'standard'
    if ($isAdmin) { $elevation = 'elevated' }
    elseif ($tokenSids -contains 'S-1-5-32-544') { $elevation = 'filtered_admin' }

    $privs = foreach ($r in (Get-WhoamiCsv '/priv' @('name', 'description', 'state'))) {
        [PSCustomObject]@{ name = $r.name; description = $r.description; state = $r.state }
    }

    [PSCustomObject]@{
        user          = $id.Name
        sid           = $id.User.Value
        is_admin      = [bool]$isAdmin
        elevation     = $elevation
        integrity     = $integrity
        integrity_sid = $label
        groups        = @($groups)
        privileges    = @($privs)
    }
}

function Get-OsFacts {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $cv = $null
    try { $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop } catch {}
    [PSCustomObject]@{
        caption         = $os.Caption
        version         = $os.Version
        build_number    = $os.BuildNumber
        ubr             = if ($cv) { $cv.UBR } else { $null }
        display_version = if ($cv) { $cv.DisplayVersion } else { $null }
        release_id      = if ($cv) { $cv.ReleaseId } else { $null }
        architecture    = $os.OSArchitecture
        install_date    = if ($os.InstallDate) { $os.InstallDate.ToString('o') } else { $null }
        hostname        = $env:COMPUTERNAME
        domain          = if ($cs) { $cs.Domain } else { $null }
        part_of_domain  = if ($cs) { [bool]$cs.PartOfDomain } else { $null }
    }
}

function Get-PatchFacts {
    try {
        Get-HotFix -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                hotfix_id    = $_.HotFixID
                description  = $_.Description
                installed_on = if ($_.InstalledOn) { $_.InstalledOn.ToString('o') } else { $null }
            }
        }
    } catch { @() }
}

function Get-ServiceFacts {
    $svcs = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
    foreach ($s in $svcs) {
        $img = Expand-ImagePath (Resolve-ImagePath $s.PathName)
        Add-AclFactWithAncestors $img
        [PSCustomObject]@{
            name          = $s.Name
            display_name  = $s.DisplayName
            state         = $s.State
            start_mode    = $s.StartMode
            run_as        = $s.StartName
            run_as_sid    = ConvertTo-Sid $s.StartName
            path_name_raw = $s.PathName
            image_path    = $img
            image_dir     = Get-ParentDir $img
            reg_key       = (Add-RegAcl "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)")
        }
    }
}

function Get-ScheduledTaskFacts {
    try { $tasks = Get-ScheduledTask -ErrorAction Stop } catch { return @() }
    foreach ($t in $tasks) {
        $actions = foreach ($a in $t.Actions) {
            $exe = Expand-ImagePath $a.Execute
            Add-AclFactWithAncestors $exe
            [PSCustomObject]@{
                execute    = $a.Execute
                arguments  = $a.Arguments
                image_path = $exe
                image_dir  = Get-ParentDir $exe
            }
        }
        [PSCustomObject]@{
            name         = $t.TaskName
            path         = $t.TaskPath
            state        = "$($t.State)"
            run_as           = $t.Principal.UserId
            run_as_sid       = ConvertTo-Sid $t.Principal.UserId
            run_as_group     = $t.Principal.GroupId
            run_as_group_sid = ConvertTo-Sid $t.Principal.GroupId
            logon_type       = "$($t.Principal.LogonType)"
            run_level    = "$($t.Principal.RunLevel)"
            actions      = @($actions)
        }
    }
}

function Get-PathDirFacts {
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user    = [Environment]::GetEnvironmentVariable('Path', 'User')
    $seen = @{}
    $out = @()
    foreach ($scope in @(@{ s = 'Machine'; v = $machine }, @{ s = 'User'; v = $user })) {
        if (-not $scope.v) { continue }
        foreach ($d in ($scope.v -split ';')) {
            $dd = $d.Trim()
            if (-not $dd) { continue }
            $expanded = [Environment]::ExpandEnvironmentVariables($dd)
            $key = "$($scope.s)|$($expanded.ToLowerInvariant())"
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            Add-AclFactWithAncestors $expanded
            $out += [PSCustomObject]@{ scope = $scope.s; dir = $expanded }
        }
    }
    $out
}

function Get-AutorunFacts {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    $out = @()
    foreach ($k in $keys) {
        if (-not (Test-Path $k)) { continue }
        $props = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            $val = [string]$p.Value
            $img = Expand-ImagePath (Resolve-ImagePath $val)
            Add-AclFactWithAncestors $img
            $out += [PSCustomObject]@{
                hive       = $k
                name       = $p.Name
                value      = $val
                image_path = $img
                image_dir  = Get-ParentDir $img
            }
        }
    }
    $out
}

# Registry execution-hook points: record where a hook is set, its value, and the program it
# resolves to (added to the ACL table). Read-only. The analyzer flags a hook whose target a
# non-admin can overwrite or create. Writable-key detection (setting a hook from scratch) is a
# separate, later facts section; this one is value + target-file only.
function Get-ExecHookFacts {
    $script:HookOut = New-Object System.Collections.ArrayList
    function HookAdd($type, $location, $name, $value, $kind, $extra) {
        $img = Resolve-HookModule $value $kind
        Add-AclFactWithAncestors $img
        $rec = [ordered]@{
            type = $type; location = $location; name = $name; value = $value
            image_path = $img; image_dir = (Get-ParentDir $img)
        }
        if ($extra) { foreach ($k in $extra.Keys) { $rec[$k] = $extra[$k] } }
        [void]$script:HookOut.Add([PSCustomObject]$rec)
    }

    # Image File Execution Options: a Debugger value hijacks the named program.
    foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
                        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
        if (-not (Test-Path $base)) { continue }
        Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object {
            $dbg = (Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
            if ($dbg) { HookAdd 'ifeo_debugger' "IFEO\$($_.PSChildName)\Debugger" $_.PSChildName $dbg 'exe' $null }
        }
    }
    $spe = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
    if (Test-Path $spe) {
        Get-ChildItem $spe -ErrorAction SilentlyContinue | ForEach-Object {
            $mp = (Get-ItemProperty $_.PSPath -Name MonitorProcess -ErrorAction SilentlyContinue).MonitorProcess
            if ($mp) { HookAdd 'silent_process_exit' "SilentProcessExit\$($_.PSChildName)\MonitorProcess" $_.PSChildName $mp 'exe' $null }
        }
    }

    # AppInit_DLLs: loaded into every process that links user32 (when LoadAppInit_DLLs is on).
    foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
                        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
        $p = Get-ItemProperty $base -ErrorAction SilentlyContinue
        if (-not $p -or -not $p.AppInit_DLLs) { continue }
        $enabled = [bool]$p.LoadAppInit_DLLs
        $signed = [bool]$p.RequireSignedAppInit_DLLs
        $sep = if ($p.AppInit_DLLs -match ',') { ',' } else { ' ' }
        foreach ($d in (($p.AppInit_DLLs -split $sep) | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
            HookAdd 'appinit_dll' "$base\AppInit_DLLs" $d $d 'dll' @{ enabled = $enabled; signed_required = $signed }
        }
    }

    # AppCertDlls: loaded into processes that call CreateProcess and friends.
    $acd = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
    if (Test-Path $acd) {
        $p = Get-ItemProperty $acd -ErrorAction SilentlyContinue
        if ($p) { foreach ($prop in $p.PSObject.Properties) { if ($prop.Name -like 'PS*') { continue }; HookAdd 'appcert_dll' "AppCertDlls\$($prop.Name)" $prop.Name ([string]$prop.Value) 'dll' $null } }
    }

    # Winlogon: Userinit/Shell/Taskman run at logon.
    $wp = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
    if ($wp) {
        foreach ($u in (($wp.Userinit -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })) { HookAdd 'winlogon_userinit' 'Winlogon\Userinit' 'Userinit' $u 'exe' $null }
        if ($wp.Shell) { HookAdd 'winlogon_shell' 'Winlogon\Shell' 'Shell' ([string]$wp.Shell) 'exe' $null }
        if ($wp.Taskman) { HookAdd 'winlogon_taskman' 'Winlogon\Taskman' 'Taskman' ([string]$wp.Taskman) 'exe' $null }
    }

    # Active Setup: StubPath runs once per user at logon.
    foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components',
                        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components')) {
        if (-not (Test-Path $base)) { continue }
        Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object {
            $sp = (Get-ItemProperty $_.PSPath -Name StubPath -ErrorAction SilentlyContinue).StubPath
            if ($sp) { HookAdd 'active_setup' "ActiveSetup\$($_.PSChildName)\StubPath" $_.PSChildName ([string]$sp) 'exe' $null }
        }
    }

    # LSA packages: loaded into LSASS as SYSTEM.
    $lp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    if ($lp) {
        foreach ($vn in @('Security Packages', 'Authentication Packages', 'Notification Packages')) {
            foreach ($m in @($lp.$vn)) { if ($m -and $m -ne '""') { HookAdd 'lsa_package' "Lsa\$vn" $m $m 'dll' $null } }
        }
    }

    # Print monitors: Driver DLL loaded by the spooler (SYSTEM).
    $pm = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors'
    if (Test-Path $pm) {
        Get-ChildItem $pm -ErrorAction SilentlyContinue | ForEach-Object {
            $drv = (Get-ItemProperty $_.PSPath -Name Driver -ErrorAction SilentlyContinue).Driver
            if ($drv) { HookAdd 'print_monitor' "Monitors\$($_.PSChildName)\Driver" $_.PSChildName ([string]$drv) 'dll' $null }
        }
    }

    # Netsh helper DLLs: loaded when netsh runs.
    $ns = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Netsh' -ErrorAction SilentlyContinue
    if ($ns) { foreach ($prop in $ns.PSObject.Properties) { if ($prop.Name -like 'PS*') { continue }; HookAdd 'netsh_helper' "Netsh\$($prop.Name)" $prop.Name ([string]$prop.Value) 'dll' $null } }

    $script:HookOut
}

function Get-PolicyFacts {
    function RegVal($path, $name) {
        try { return (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name } catch { return $null }
    }
    [PSCustomObject]@{
        always_install_elevated = [PSCustomObject]@{
            hklm = RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
            hkcu = RegVal 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
        }
        uac = [PSCustomObject]@{
            enable_lua                        = RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
            consent_prompt_behavior_admin     = RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin'
            prompt_on_secure_desktop          = RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'PromptOnSecureDesktop'
            local_account_token_filter_policy = RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy'
            filter_administrator_token        = RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'FilterAdministratorToken'
        }
        lsa = [PSCustomObject]@{
            run_as_ppl             = RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
            lm_compatibility_level = RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
            restrict_anonymous     = RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous'
            no_lm_hash             = RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLmHash'
        }
        wdigest_use_logon_credential = RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
        point_and_print = [PSCustomObject]@{
            restrict_driver_install_to_admins  = RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' 'RestrictDriverInstallationToAdministrators'
            no_warning_no_elevation_on_install = RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' 'NoWarningNoElevationOnInstall'
            update_prompt_settings             = RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' 'UpdatePromptSettings'
        }
        wsus = [PSCustomObject]@{
            wu_server        = RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'WUServer'
            wu_status_server = RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'WUStatusServer'
            use_wu_server    = RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'UseWUServer'
        }
    }
}

# Secret-bearing artifacts: record PRESENCE, metadata and the file's ACL only. Contents and
# stored password values are never read.
function Get-CredentialArtifactFacts {
    $out = @()
    $files = @(
        "$env:WINDIR\Panther\Unattend.xml",
        "$env:WINDIR\Panther\Unattended.xml",
        "$env:WINDIR\Panther\Unattend\Unattend.xml",
        "$env:WINDIR\System32\Sysprep\unattend.xml",
        "$env:WINDIR\System32\Sysprep\sysprep.xml",
        "$env:WINDIR\System32\Sysprep\Panther\unattend.xml"
    )
    foreach ($f in $files) {
        if (Test-Path -LiteralPath $f) {
            $fi = Get-Item -LiteralPath $f -ErrorAction SilentlyContinue
            Add-AclFact $f
            $out += [PSCustomObject]@{
                type       = 'unattend'
                path       = $f
                size       = if ($fi) { $fi.Length } else { $null }
                last_write = if ($fi) { $fi.LastWriteTimeUtc.ToString('o') } else { $null }
                note       = 'presence only; review contents manually'
            }
        }
    }

    $hist = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path -LiteralPath $hist) {
        $fi = Get-Item -LiteralPath $hist -ErrorAction SilentlyContinue
        $out += [PSCustomObject]@{
            type       = 'psreadline_history'
            path       = $hist
            size       = if ($fi) { $fi.Length } else { $null }
            last_write = if ($fi) { $fi.LastWriteTimeUtc.ToString('o') } else { $null }
            note       = 'presence only; contents not read'
        }
    }

    # Autologon: whether it is enabled and whether a DefaultPassword value EXISTS.
    # The value itself is never read.
    try {
        $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $p = Get-ItemProperty -Path $wl -ErrorAction Stop
        $hasPw = $null -ne ($p.PSObject.Properties.Name | Where-Object { $_ -eq 'DefaultPassword' })
        if ($p.AutoAdminLogon -or $hasPw) {
            $out += [PSCustomObject]@{
                type                     = 'autologon'
                path                     = $wl
                auto_admin_logon         = "$($p.AutoAdminLogon)"
                default_username         = $p.DefaultUserName
                default_password_present = [bool]$hasPw
                note                     = 'DefaultPassword value is NOT read by the collector'
            }
        }
    } catch {}

    $out
}

# --- main -----------------------------------------------------------------------------

$start = Get-Date

$report = [ordered]@{
    privscope = [ordered]@{
        tool           = 'privscope-collector'
        platform       = 'windows'
        version        = '0.1.0'
        schema_version = 1
        kind           = 'collection'
        read_only      = $true
    }
    run = [ordered]@{
        collected_at   = (Get-Date).ToUniversalTime().ToString('o')
        collector_user = $env:USERNAME
        ps_version     = $PSVersionTable.PSVersion.ToString()
    }
    host      = Get-OsFacts
    principal = Get-PrincipalFacts
    facts = [ordered]@{
        patches              = @(Get-PatchFacts)
        services             = @(Get-ServiceFacts)
        scheduled_tasks      = @(Get-ScheduledTaskFacts)
        autoruns             = @(Get-AutorunFacts)
        exec_hooks           = @(Get-ExecHookFacts)
        reg_keys             = @(Get-RegKeyFacts)
        path_dirs            = @(Get-PathDirFacts)
        policies             = Get-PolicyFacts
        credential_artifacts = @(Get-CredentialArtifactFacts)
    }
}
$report.facts['acls'] = $script:AclTable
$report.facts['reg_acls'] = $script:RegAclTable
$report.run['duration_ms'] = [int]((Get-Date) - $start).TotalMilliseconds

$json = $report | ConvertTo-Json -Depth 12 -Compress

if (-not $OutFile) {
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $OutFile = Join-Path (Get-Location) ("privscope-{0}-{1}.json" -f $env:COMPUTERNAME, $stamp)
}
$json | Out-File -FilePath $OutFile -Encoding UTF8
Write-Host "[privscope] read-only collection written to $OutFile"
if ($Stdout) { $json }
