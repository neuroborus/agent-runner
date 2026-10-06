# Definitions only. The separately approved preparation transport invokes this
# entry after persisting the exact request. This slice registers/starts no task.
function Open-NativePrerequisiteGateway {
  param([string] $IntentPath, [string] $IntentSha256, [string] $ApprovalJson, [switch] $Recover)
  $ErrorActionPreference = 'Stop'
  if ($PSVersionTable.PSEdition -ne 'Core' -or $PSVersionTable.PSVersion.Major -ne 7) { throw 'Approved PowerShell 7 Core required' }
  if ($IntentSha256 -cnotmatch '^[a-f0-9]{64}$' -or $ApprovalJson.Length -gt 4096) { throw 'Invalid gateway approval' }
  $approval = $ApprovalJson | ConvertFrom-Json
  foreach ($key in @('nodeSha256', 'hostSha256', 'sourceSha256', 'privilegeSha256')) {
    if ($approval.$key -cnotmatch '^[a-f0-9]{64}$') { throw 'Missing independent gateway approval' }
  }
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Approved elevated gateway required' }
  if (-not ('NativePrerequisiteGateway' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class NativePrerequisiteGateway {
  [DllImport("kernel32", CharSet=CharSet.Unicode, SetLastError=true)] static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sd, uint disposition, uint flags, IntPtr template);
  [DllImport("kernel32", SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int kind, byte[] info, uint size);
  [DllImport("kernel32", CharSet=CharSet.Unicode, SetLastError=true)] static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint size, uint flags);
  [DllImport("advapi32")] static extern uint GetSecurityInfo(SafeFileHandle handle, uint kind, uint flags, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr sd);
  [DllImport("advapi32")] static extern uint GetSecurityDescriptorLength(IntPtr sd);
  [DllImport("kernel32")] static extern IntPtr LocalFree(IntPtr memory);
  public static SafeFileHandle Parent(string path) {
    SafeFileHandle handle = CreateFileW(path, 0x20080, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
    if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
    return handle;
  }
  public static string Identity(SafeFileHandle handle, string path, bool directory) {
    byte[] attributes = new byte[8], id = new byte[24], standard = new byte[24];
    if (!GetFileInformationByHandleEx(handle, 9, attributes, 8) || !GetFileInformationByHandleEx(handle, 18, id, 24) || !GetFileInformationByHandleEx(handle, 1, standard, 24)) throw new Win32Exception(Marshal.GetLastWin32Error());
    uint flags = BitConverter.ToUInt32(attributes, 0);
    StringBuilder name = new StringBuilder(4100); uint size = GetFinalPathNameByHandleW(handle, name, 4100, 0);
    if ((flags & 0x400) != 0 || ((flags & 0x10) != 0) != directory || standard[20] != 0 || (!directory && BitConverter.ToUInt32(standard, 16) != 1) || size <= 4 || size >= 4100 || !name.ToString().StartsWith("\\\\?\\") || !String.Equals(name.ToString().Substring(4), path, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Changed gateway object");
    return Convert.ToHexString(id).ToLowerInvariant();
  }
  public static RawSecurityDescriptor Security(SafeFileHandle handle) {
    IntPtr owner, group, dacl, sacl, sd;
    uint error = GetSecurityInfo(handle, 1, 5, out owner, out group, out dacl, out sacl, out sd);
    if (error != 0) throw new Win32Exception((int)error);
    try {
      uint size = GetSecurityDescriptorLength(sd);
      if (size == 0 || size > 65536) throw new InvalidOperationException("Invalid gateway security");
      byte[] bytes = new byte[size]; Marshal.Copy(sd, bytes, 0, (int)size);
      return new RawSecurityDescriptor(bytes, 0);
    } finally { LocalFree(sd); }
  }
}
'@
  }
  function Assert-Path([string] $Path) {
    if ($Path.Length -gt 4096 -or $Path -cnotmatch '^[A-Za-z]:\\[^:]+$' -or [IO.Path]::GetFullPath($Path) -cne $Path -or $Path -match '[\x00-\x1f\x7f]') { throw 'Invalid gateway path' }
    foreach ($part in $Path.Substring(3).Split('\')) {
      if (-not $part -or $part -match '[<>"|?*]|[. ]$|^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\.|$)') { throw 'Invalid gateway component' }
    }
  }
  function Digest([byte[]] $Bytes) { [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant() }
  function Assert-Security($Handle, [bool] $Private) {
    $sd = [NativePrerequisiteGateway]::Security($Handle)
    if ($null -eq $sd.Owner -or $null -eq $sd.DiscretionaryAcl -or $sd.Owner.Value -notin $trusted) { throw 'Unprotected gateway owner' }
    foreach ($ace in $sd.DiscretionaryAcl) {
      if ($ace -isnot [Security.AccessControl.CommonAce] -or $ace.IsCallback -or $ace.AceQualifier -notin @('AccessAllowed', 'AccessDenied')) { throw 'Unsupported gateway ACE' }
      if ($ace.AceQualifier -eq 'AccessAllowed' -and $ace.SecurityIdentifier.Value -notin $trusted -and ([long]$ace.AccessMask -band 0x500d0156)) { throw 'Foreign gateway writer' }
      if ($Private -and $ace.SecurityIdentifier.Value -notin @($controller, 'S-1-5-18')) { throw 'Non-private gateway object' }
    }
    if ($Private -and -not ($sd.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)) { throw 'Inherited gateway access' }
    return $sd.GetSddlForm([Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access)
  }
  $controller = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $trusted = @('S-1-5-18', 'S-1-5-32-544', $controller, 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
  $retained = [Collections.Generic.List[IDisposable]]::new()
  $objects = [Collections.Generic.List[object]]::new()
  # Retain uncertain handles in this host. Interruption leaves the immutable
  # request authoritative; matching bytes never authorize adoption or removal.
  if (-not $script:NativePrerequisiteGatewayCustody) { $script:NativePrerequisiteGatewayCustody = [Collections.Generic.List[object]]::new() }
  $custody = @{ Handles = $retained; Objects = $objects; IntentPath = $IntentPath; IntentSha256 = $IntentSha256; Reservation = 'RETAINED'; CustodianRetired = $false; Admitted = $false; BirthProtected = $false }
  $script:NativePrerequisiteGatewayCustody.Add($custody)
  function Hold-Parents([string] $Path) {
    $chain = [Collections.Generic.List[string]]::new()
    for ($current = [IO.Path]::GetDirectoryName($Path); $current; $current = [IO.Path]::GetDirectoryName($current)) { $chain.Insert(0, $current); if ($chain.Count -gt 64) { throw 'Too many gateway parents' } }
    foreach ($parent in $chain) {
      $handle = [NativePrerequisiteGateway]::Parent($parent); $retained.Add($handle)
      $objects.Add(@{ Path = $parent; Identity = [NativePrerequisiteGateway]::Identity($handle, $parent, $true); Security = Assert-Security $handle $false })
    }
  }
  Assert-Path $IntentPath; Hold-Parents $IntentPath
  $intent = [IO.FileStream]::new($IntentPath, 'Open', 'Read', 'Read'); $retained.Add($intent)
  $intentId = [NativePrerequisiteGateway]::Identity($intent.SafeFileHandle, $IntentPath, $false)
  $null = Assert-Security $intent.SafeFileHandle $true
  if ($intent.Length -eq 0 -or $intent.Length -gt 8388608) { throw 'Invalid gateway intent length' }
  $bytes = [byte[]]::new($intent.Length)
  $intent.ReadExactly($bytes, 0, $bytes.Length)
  if ((Digest $bytes) -cne $IntentSha256) { throw 'Changed gateway intent' }
  $custody.IntentIdentity = $intentId
  $r = [Text.UTF8Encoding]::new($false, $true).GetString($bytes) | ConvertFrom-Json
  $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  if ($r.schemaVersion -ne 1 -or $r.platform -cne 'win32' -or $r.expires -le 0 -or
    (-not $Recover -and ($r.expires -le $now -or $r.expires - $now -gt 120000)) -or
    $r.admission.nonce -cnotmatch '^[a-f0-9]{32}$' -or $r.admission.platform -cne 'win32' -or $r.admission.controllerSid -cne $controller -or $r.expires -ne $r.admission.expires) { throw 'Invalid gateway admission' }
  if ($approval.nodeSha256 -cne $r.node.sha256 -or $approval.hostSha256 -cne $r.host.sha256 -or
    $approval.sourceSha256 -cne (Digest ([Text.Encoding]::UTF8.GetBytes(($r.source | ConvertTo-Json -Depth 8 -Compress)))) -or
    $approval.privilegeSha256 -cne (Digest ([Text.Encoding]::UTF8.GetBytes(($r.privilege | ConvertTo-Json -Compress)))) -or
    $r.privilege.userSid -cne 'S-1-5-18' -or $r.privilege.sessionId -ne 0 -or $r.privilege.task -cne 'exclusive' -or $r.privilege.pipe -cne 'private') { throw 'Missing independent gateway approval' }
  if ($r.host.path -cne 'C:\Program Files\PowerShell\7\pwsh.exe' -or [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName -cne $r.host.path) { throw 'Wrong gateway interpreter' }
  # System scheduled tasks inherit machine configuration. A cleared controller
  # environment cannot replace independent inspection of these startup keys.
  foreach ($path in @('HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Registry::HKEY_USERS\S-1-5-18\Environment')) {
    if (Test-Path -LiteralPath $path) {
      $key = Get-Item -LiteralPath $path
      foreach ($variable in $key.GetValueNames()) {
        if ($variable -match '^(NODE_.+|OPENSSL_CONF|OPENSSL_MODULES|DOTNET_STARTUP_HOOKS|DOTNET_ADDITIONAL_DEPS|CORECLR_.+|COMPLUS_.+|COR_ENABLE_PROFILING|COR_PROFILER.*)$' -and $key.GetValue($variable)) { throw 'Unapproved System interpreter configuration' }
      }
    }
  }
  foreach ($pin in @($r.node, $r.host)) {
    Assert-Path $pin.path; Hold-Parents $pin.path
    $image = [IO.FileStream]::new($pin.path, 'Open', 'Read', 'Read'); $retained.Add($image)
    $id = [NativePrerequisiteGateway]::Identity($image.SafeFileHandle, $pin.path, $false)
    $security = Assert-Security $image.SafeFileHandle $false
    if ($pin.bytes -le 0 -or $pin.bytes -gt 536870912 -or $image.Length -ne $pin.bytes -or [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($image)).ToLowerInvariant() -cne $pin.sha256) { throw 'Changed gateway host' }
    $objects.Add(@{ Path = $pin.path; Identity = $id; Security = $security })
  }
  Assert-Path $r.output; Assert-Path $r.worker.source.path
  Assert-Path $r.admission.root
  if (-not $r.output.StartsWith($r.admission.root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Escaped gateway output' }
  $name = 'AgentRunnerPrerequisites-' + $r.admission.nonce
  if ($r.worker.taskName -cne $name -or $r.worker.file -cne $r.node.path -or $r.worker.args.Count -ne 2 -or
    $r.worker.args[0] -cne $r.worker.source.path -or $r.worker.args[1] -cne ('\\.\pipe\' + $name) -or
    $r.worker.source.path -cne [IO.Path]::Combine($r.output, 'prerequisite-worker-' + $r.admission.nonce + '.mjs')) { throw 'Invalid gateway worker vector' }
  $custody.TaskName = $name
  $workerBytes = [Text.Encoding]::UTF8.GetBytes($r.worker.source.text)
  if ($workerBytes.Length -ne $r.worker.source.bytes -or $workerBytes.Length -eq 0 -or $workerBytes.Length -gt 4194304 -or (Digest $workerBytes) -cne $r.worker.source.sha256) { throw 'Changed gateway worker snapshot' }
  Hold-Parents $r.worker.source.path
  if ($Recover) {
    # No creation, task, pipe or write is retried during reconstruction.
    if ([IO.File]::Exists($r.worker.source.path)) {
      $possible = [IO.FileStream]::new($r.worker.source.path, 'Open', 'Read', 'Read'); $retained.Add($possible)
      $objects.Add(@{ Path = $r.worker.source.path; Identity = [NativePrerequisiteGateway]::Identity($possible.SafeFileHandle, $r.worker.source.path, $false); Security = Assert-Security $possible.SafeFileHandle $true })
    }
    $custody.IntentIdentity = $intentId; $custody.Admitted = $false; $custody.BirthProtected = $false
    return $custody
  }
  $workerSd = [Security.AccessControl.FileSecurity]::new()
  $workerSd.SetOwner([Security.Principal.SecurityIdentifier]::new($controller)); $workerSd.SetAccessRuleProtection($true, $false)
  $workerSd.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($controller), 'FullControl', 'Allow'))
  $workerSd.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-18'), 'ReadAndExecute', 'Allow'))
  if ($r.expires -le [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()) { throw 'Expired gateway preparation' }
  $writer = [IO.FileSystemAclExtensions]::Create([IO.FileInfo]::new($r.worker.source.path), 'CreateNew', 'FullControl', 'Read', 4096, 'None', $workerSd); $retained.Add($writer)
  $birth = [NativePrerequisiteGateway]::Identity($writer.SafeFileHandle, $r.worker.source.path, $false)
  $null = Assert-Security $writer.SafeFileHandle $true
  $writer.Write($workerBytes, 0, $workerBytes.Length); $writer.Flush($true); $writer.Dispose()
  $image = [IO.FileStream]::new($r.worker.source.path, 'Open', 'Read', 'Read'); $retained.Add($image)
  $sealed = [NativePrerequisiteGateway]::Identity($image.SafeFileHandle, $r.worker.source.path, $false)
  if ($birth -cne $sealed -or $image.Length -ne $workerBytes.Length -or [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($image)).ToLowerInvariant() -cne $r.worker.source.sha256) { throw 'Changed held worker identity/bytes' }
  $objects.Add(@{ Path = $r.worker.source.path; Identity = $sealed; Security = Assert-Security $image.SafeFileHandle $true })
  $sd = [Security.AccessControl.PipeSecurity]::new(); $sd.SetAccessRuleProtection($true, $false)
  foreach ($sid in @($controller, 'S-1-5-18')) { $sd.AddAccessRule([Security.AccessControl.PipeAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'Allow')) }
  if ($r.expires -le [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()) { throw 'Expired gateway preparation' }
  $pipe = [IO.Pipes.NamedPipeServerStreamAcl]::Create($name, 'InOut', 1, 'Byte', ([IO.Pipes.PipeOptions]::Asynchronous -bor [IO.Pipes.PipeOptions]::FirstPipeInstance), 65536, 65536, $sd); $retained.Add($pipe)
  $custody.Pipe = $pipe
  $service = New-Object -ComObject 'Schedule.Service'; $service.Connect()
  $task = $service.NewTask(0)
  $task.Principal.UserId = 'S-1-5-18'; $task.Principal.LogonType = 5; $task.Principal.RunLevel = 1
  $task.Settings.ExecutionTimeLimit = 'PT120S'; $task.Settings.AllowHardTerminate = $false
  $task.Settings.DisallowStartIfOnBatteries = $false; $task.Settings.StopIfGoingOnBatteries = $false
  $action = $task.Actions.Create(0); $action.Path = $r.worker.file
  function Quote-Argument([string] $Value) { '"' + [regex]::Replace([regex]::Replace($Value, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"' }
  $action.Arguments = ($r.worker.args | ForEach-Object { Quote-Argument $_ }) -join ' '
  if ($action.Arguments.Length + $action.Path.Length -gt 32760) { throw 'Oversized gateway vector' }
  $action.WorkingDirectory = $r.output
  # Task registration, release, independent native settlement and reconstruction
  # belong to the later transport/verifier. A prepared vector grants no release.
  $custody.IntentIdentity = $intentId; $custody.TaskName = $name; $custody.Task = $task; $custody.Pipe = $pipe
  $custody.TaskSddl = 'O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;' + $controller + ')'
  $custody.Admitted = $false; $custody.BirthProtected = $true
  return $custody
}

function Close-NativePrerequisiteGateway {
  param($Custody)
  foreach ($handle in $Custody.Handles) { $handle.Dispose() }
  $Custody.Handles.Clear()
  $Custody.Reservation = 'RETAINED'; $Custody.CustodianRetired = $false
  return @{ Status = 'CLOSED'; CustodianRetired = $false; Reservation = 'RETAINED' }
}
