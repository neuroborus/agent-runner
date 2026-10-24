import { createHash } from "node:crypto";
import { win32 } from "node:path";

import {
  observationDigest,
  observationObject,
  requireObservation,
} from "./observation.js";
import {
  PREREQUISITE_FILE_LIMITS,
  prerequisiteCreationRequest,
} from "./prerequisite-files.js";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const CHUNK_BYTES = 32768;
const FRAME_BYTES = 65536;
const canonical = (file) =>
  typeof file === "string" &&
  file.length <= 4096 &&
  win32.normalize(file) === file &&
  /^[A-Za-z]:\\[^:]+$/u.test(file) &&
  !/[\u0000-\u001f\u007f]/u.test(file) &&
  file
    .slice(3)
    .split("\\")
    .every(
      (part) =>
        part &&
        !/[<>"|?*]|[. ]$/u.test(part) &&
        !/^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/iu.test(part),
    );

/** Fixed stock-host interop source. Loading this JavaScript has no effects;
 * even the PowerShell source only defines an entry. A separately admitted
 * source/host/custody transport must explicitly invoke it. No PATH fallback,
 * child process, task, compiler command, or pipe is started by this module. */
export const WINDOWS_PREREQUISITE_FILES_SOURCE = String.raw`
function Invoke-NativePrerequisiteFile {
  param($Request)
  $ErrorActionPreference = 'Stop'
  if ($Request.schemaVersion -ne 1 -or $Request.operation -notin @('create','write','seal','hold','read','observe','close')) { throw 'Undeclared file operation' }
  if ($PSVersionTable.PSEdition -ne 'Core' -or $PSVersionTable.PSVersion.Major -ne 7) { throw 'Reviewed in-process stock host required' }
  if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18' -or [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0) { throw 'System custody required' }
  if (-not ('NativePrerequisiteFiles' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class NativePrerequisiteFiles {
  [StructLayout(LayoutKind.Sequential)] struct Attributes { public uint Size; public IntPtr Descriptor; public int Inherit; }
  [StructLayout(LayoutKind.Sequential)] struct Info { public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh, Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow; }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateDirectoryW(string name, ref Attributes security);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int kind, byte[] info, uint size);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder name, uint size, uint flags);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetFilePointerEx(SafeFileHandle handle, long offset, out long position, uint method);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool WriteFile(SafeFileHandle handle, byte[] bytes, uint count, out uint written, IntPtr overlapped);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadFile(SafeFileHandle handle, byte[] bytes, uint count, out uint read, IntPtr overlapped);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool FlushFileBuffers(SafeFileHandle handle);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetHandleInformation(IntPtr handle, out uint flags);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text, uint revision, out IntPtr descriptor, out uint size);
  [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(SafeFileHandle handle, int kind, uint information, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
  [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
  sealed class Entry { public SafeFileHandle Handle; public string Id; public bool Writer; public bool Created; }
  static readonly Dictionary<string, Entry> files = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
  static readonly Dictionary<string, Entry> parents = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
  static readonly List<SafeFileHandle> handles = new List<SafeFileHandle>();
  static readonly HashSet<SafeFileHandle> closed = new HashSet<SafeFileHandle>();
  static bool fenced;
  static void Need(bool value) { if (!value) throw new IOException("Unverified Windows prerequisite custody"); }
  static string Hex(byte[] bytes) { return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant(); }
  static bool Inside(string root, string path) { return path.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase); }
  static void Release(SafeFileHandle handle) {
    IntPtr native = handle.DangerousGetHandle(); handle.Dispose(); uint flags;
    Need(!GetHandleInformation(native, out flags) && Marshal.GetLastWin32Error() == 6); closed.Add(handle);
  }
  static void PathCheck(string path) {
    Need(path != null && path.Length <= 4096 && path.Length > 3 && path[1] == ':' && path[2] == '\\' && Path.GetFullPath(path) == path && path.IndexOf(':', 2) < 0);
    foreach (char letter in path) Need(!Char.IsControl(letter));
    foreach (string part in path.Substring(3).Split('\\')) {
      Need(part.Length > 0 && !part.EndsWith(".") && !part.EndsWith(" ") && part.IndexOfAny(new char[] { '<', '>', '"', '|', '?', '*' }) < 0);
      string name = part.Split('.')[0].ToUpperInvariant(); Need(name != "CON" && name != "PRN" && name != "AUX" && name != "NUL" && !(name.Length == 4 && (name.StartsWith("COM") || name.StartsWith("LPT")) && Char.IsDigit(name[3])));
    }
  }
  static SafeFileHandle Open(string path, bool directory, bool writer, uint disposition, IntPtr security, uint share) {
    SafeFileHandle handle = CreateFileW(path, (writer ? 0xc0000000u : directory ? 1u : 0x80000000u) | 0x20000u | 0x80u, share, security, disposition, 0x200000u | (directory ? 0x2000000u : 0u), IntPtr.Zero);
    Need(!handle.IsInvalid); handles.Add(handle); return handle;
  }
  static string Id(SafeFileHandle handle) {
    byte[] id = new byte[24]; Need(GetFileInformationByHandleEx(handle, 18, id, 24)); return Hex(id);
  }
  static RawSecurityDescriptor Descriptor(SafeFileHandle handle) {
    IntPtr owner, group, dacl, sacl, descriptor;
    Need(GetSecurityInfo(handle, 1, 5, out owner, out group, out dacl, out sacl, out descriptor) == 0 && dacl != IntPtr.Zero);
    try { uint size = GetSecurityDescriptorLength(descriptor); Need(size > 0 && size <= 65536); byte[] bytes = new byte[size]; Marshal.Copy(descriptor, bytes, 0, bytes.Length); return new RawSecurityDescriptor(bytes, 0); }
    finally { LocalFree(descriptor); }
  }
  static object Security(SafeFileHandle handle, bool privateObject, string controller) {
    RawSecurityDescriptor sd = Descriptor(handle); Need(sd.Owner != null && sd.DiscretionaryAcl != null);
    var privileged = new HashSet<string> { "S-1-5-18", "S-1-5-32-544", controller, "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" };
    Need(privileged.Contains(sd.Owner.Value)); var rules = new List<object>();
    foreach (GenericAce raw in sd.DiscretionaryAcl) {
      CommonAce ace = raw as CommonAce; Need(ace != null && !ace.IsCallback && (ace.AceQualifier == AceQualifier.AccessAllowed || ace.AceQualifier == AceQualifier.AccessDenied));
      bool allow = ace.AceQualifier == AceQualifier.AccessAllowed; uint mask = unchecked((uint)ace.AccessMask);
      Need(!allow || privileged.Contains(ace.SecurityIdentifier.Value) || (mask & 0x500d0156u) == 0);
      rules.Add(new Dictionary<string, object> { { "sid", ace.SecurityIdentifier.Value }, { "rights", mask }, { "allow", allow }, { "inherited", (ace.AceFlags & AceFlags.Inherited) != 0 } });
    }
    if (privateObject) {
      Need(sd.Owner.Value == "S-1-5-18" && (sd.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0 && sd.DiscretionaryAcl.Count == 1);
      CommonAce ace = sd.DiscretionaryAcl[0] as CommonAce;
      Need(ace != null && ace.AceFlags == AceFlags.None && ace.AceQualifier == AceQualifier.AccessAllowed && ace.SecurityIdentifier.Value == "S-1-5-18" && unchecked((uint)ace.AccessMask) == 0x1f01ffu);
    }
    return new Dictionary<string, object> { { "owner", sd.Owner.Value }, { "protected", (sd.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0 }, { "sddl", sd.GetSddlForm(AccessControlSections.Owner | AccessControlSections.Access) }, { "rules", rules } };
  }
  static Dictionary<string, object> Observe(string path, Entry entry, bool directory, bool privateObject, string controller) {
    Info info = new Info(); Need(!entry.Handle.IsClosed && GetFileInformationByHandle(entry.Handle, out info));
    Need((info.Attributes & 0x400u) == 0 && ((info.Attributes & 0x10u) != 0) == directory && (directory || info.Links == 1));
    StringBuilder name = new StringBuilder(4100); uint length = GetFinalPathNameByHandleW(entry.Handle, name, 4100, 0);
    Need(length > 4 && length < 4100 && name.ToString().StartsWith("\\\\?\\") && String.Equals(name.ToString().Substring(4), path, StringComparison.OrdinalIgnoreCase));
    string id = Id(entry.Handle); Need(id == entry.Id);
    byte[] basic = new byte[40]; Need(GetFileInformationByHandleEx(entry.Handle, 0, basic, 40)); Array.Clear(basic, 8, 8); Array.Clear(basic, 36, 4);
    return new Dictionary<string, object> { { "file", path }, { "identity", id }, { "bytes", ((ulong)info.SizeHigh << 32) | info.SizeLow }, { "links", info.Links }, { "metadata", Hex(basic) }, { "security", Security(entry.Handle, privateObject, controller) }, { "access", entry.Writer ? "write" : "read" }, { "share", 1 } };
  }
  static IntPtr PrivateDescriptor() { IntPtr descriptor; uint size; Need(ConvertStringSecurityDescriptorToSecurityDescriptorW("O:SYG:SYD:P(A;;FA;;;SY)", 1, out descriptor, out size)); return descriptor; }
  static void Parents(string root, string file, string controller, bool create) {
    var chain = new List<string>(); string current = Path.GetDirectoryName(file);
    while (current != null) { chain.Insert(0, current); Need(chain.Count <= 64); if (current == Path.GetPathRoot(current)) break; current = Path.GetDirectoryName(current); }
    foreach (string path in chain) {
      if (create && Inside(root, path) && !Directory.Exists(path)) {
        IntPtr sd = PrivateDescriptor(); var attributes = new Attributes { Size = (uint)Marshal.SizeOf(typeof(Attributes)), Descriptor = sd, Inherit = 0 };
        try { Need(CreateDirectoryW(path, ref attributes)); } finally { LocalFree(sd); }
      }
      Entry entry;
      if (!parents.TryGetValue(path, out entry)) { SafeFileHandle handle = Open(path, true, false, 3, IntPtr.Zero, 3); entry = new Entry { Handle = handle, Id = Id(handle) }; parents.Add(path, entry); }
      Observe(path, entry, true, String.Equals(root, path, StringComparison.OrdinalIgnoreCase) || Inside(root, path), controller);
    }
  }
  public static object Call(string operation, string root, string file, string controller, long offset, int count, string data) {
    Need(!fenced); PathCheck(root); PathCheck(file); Parents(root, file, controller, operation == "create");
    Entry entry;
    if (operation == "create") {
      Need(Inside(root, file) && !files.ContainsKey(file)); IntPtr sd = PrivateDescriptor(); IntPtr memory = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Attributes)));
      try { Marshal.StructureToPtr(new Attributes { Size = (uint)Marshal.SizeOf(typeof(Attributes)), Descriptor = sd, Inherit = 0 }, memory, false); SafeFileHandle handle = Open(file, false, true, 1, memory, 1); entry = new Entry { Handle = handle, Id = Id(handle), Writer = true, Created = true }; files.Add(file, entry); }
      finally { Marshal.FreeHGlobal(memory); LocalFree(sd); }
    } else if (!files.TryGetValue(file, out entry)) {
      Need(operation == "hold"); SafeFileHandle handle = Open(file, false, false, 3, IntPtr.Zero, 1); entry = new Entry { Handle = handle, Id = Id(handle) }; files.Add(file, entry);
    }
    var before = Observe(file, entry, false, entry.Created, controller);
    if (operation == "write") {
      Need(data != null && data.Length <= 43692); byte[] bytes = Convert.FromBase64String(data); Need(entry.Writer && entry.Created && bytes.Length > 0 && bytes.Length <= 32768 && offset == Convert.ToInt64(before["bytes"]) && offset + bytes.Length <= 536870912);
      long position; uint written; Need(SetFilePointerEx(entry.Handle, offset, out position, 0) && position == offset && WriteFile(entry.Handle, bytes, (uint)bytes.Length, out written, IntPtr.Zero) && written == bytes.Length);
    } else if (operation == "seal") {
      Need(entry.Writer && FlushFileBuffers(entry.Handle));
      // Keep an identity-bearing intermediate across writer closure. The final
      // read handle denies write and delete sharing, including existing writers.
      SafeFileHandle intermediate = Open(file, false, false, 3, IntPtr.Zero, 3); Need(Id(intermediate) == entry.Id);
      Release(entry.Handle); SafeFileHandle reader = Open(file, false, false, 3, IntPtr.Zero, 1); Need(Id(reader) == entry.Id);
      entry.Handle = reader; entry.Writer = false; Release(intermediate);
    } else if (operation == "read") {
      Need(!entry.Writer && offset >= 0 && count > 0 && count <= 32768 && offset <= Convert.ToInt64(before["bytes"]));
      byte[] bytes = new byte[count]; long position; uint read = 0; Need(SetFilePointerEx(entry.Handle, offset, out position, 0) && position == offset && ReadFile(entry.Handle, bytes, (uint)count, out read, IntPtr.Zero));
      var result = Observe(file, entry, false, entry.Created, controller); Array.Resize(ref bytes, (int)read); result.Add("data", Convert.ToBase64String(bytes)); Parents(root, file, controller, false); return result;
    } else Need(operation == "create" || operation == "hold" || operation == "observe");
    Parents(root, file, controller, false); return Observe(file, entry, false, entry.Created, controller);
  }
  public static object Close() { fenced = true; foreach (SafeFileHandle handle in handles) if (!closed.Contains(handle)) Release(handle); Need(closed.Count == handles.Count); return new Dictionary<string, object> { { "status", "CLOSED" }, { "closedHandles", handles.Count }, { "custodianRetired", false } }; }
}
'@
  }
  $observed = if ($Request.operation -eq 'close') { [NativePrerequisiteFiles]::Close() } else { [NativePrerequisiteFiles]::Call($Request.operation, $Request.root, $Request.file, $Request.controllerSid, $Request.offset, $Request.count, $Request.data) }
  $frame = @{ schemaVersion = 1; requestId = $Request.requestId; operation = $Request.operation; observation = $observed } | ConvertTo-Json -Depth 12 -Compress
  if ([Text.Encoding]::UTF8.GetByteCount($frame) -gt 65536) { throw 'Oversized file observation' }
  $frame
}
`;

/** exchange is the raw IPC edge of a repository-owned admitted stock host.
 * Transport/admission defaults are deliberately not enabled in this slice. */
export function createWindowsPrerequisiteFiles(
  { root, controllerSid },
  { exchange } = {},
) {
  requireObservation(
    canonical(root) &&
      typeof controllerSid === "string" &&
      controllerSid.length <= 184 &&
      /^S-1-[0-9]+(?:-[0-9]+){1,15}$/u.test(controllerSid),
  );
  const held = new Map(),
    possible = new Set(),
    failed = new Set(),
    born = new Map();
  let requestId = 0,
    fenced = false,
    pending = Promise.resolve();
  const inside = (file) =>
    canonical(file) && file.toLowerCase().startsWith(root.toLowerCase() + "\\");
  const run = (operation) => {
    requireObservation(!fenced);
    const result = pending.then(operation);
    pending = result.catch(() => {});
    return result;
  };
  const call = async (operation, file, options = {}) => {
    requireObservation(typeof exchange === "function");
    const request = {
      schemaVersion: 1,
      requestId: ++requestId,
      operation,
      root,
      file,
      controllerSid,
      ...options,
    };
    requireObservation(
      Buffer.byteLength(JSON.stringify(request)) <= FRAME_BYTES,
    );
    const reply = await exchange(structuredClone(request));
    observationObject(reply, [
      "schemaVersion",
      "requestId",
      "operation",
      "observation",
    ]);
    requireObservation(Buffer.byteLength(JSON.stringify(reply)) <= FRAME_BYTES);
    requireObservation(
      reply?.schemaVersion === 1 &&
        reply.requestId === request.requestId &&
        reply.operation === operation,
    );
    return reply.observation;
  };
  const inspect = (value, file, access = "read") => {
    observationObject(value, [
      "file",
      "identity",
      "bytes",
      "links",
      "metadata",
      "security",
      "access",
      "share",
    ]);
    observationObject(value.security, ["owner", "protected", "sddl", "rules"]);
    requireObservation(
      value?.file === file &&
        typeof value.identity === "string" &&
        /^[a-f0-9]{48}$/u.test(value.identity) &&
        Number.isSafeInteger(value.bytes) &&
        value.bytes >= 0 &&
        value.bytes <= PREREQUISITE_FILE_LIMITS.bytes &&
        value.links === 1 &&
        typeof value.metadata === "string" &&
        /^[a-f0-9]{80}$/u.test(value.metadata) &&
        value.access === access &&
        value.share === 1 &&
        typeof value.security?.protected === "boolean" &&
        typeof value.security?.sddl === "string" &&
        value.security.sddl.length > 0 &&
        Array.isArray(value.security.rules),
    );
    const privileged = new Set([
      "S-1-5-18",
      "S-1-5-32-544",
      controllerSid,
      "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    ]);
    requireObservation(privileged.has(value.security.owner));
    for (const ace of value.security.rules) {
      observationObject(ace, ["sid", "rights", "allow", "inherited"]);
      requireObservation(
        typeof ace.sid === "string" &&
          typeof ace.allow === "boolean" &&
          typeof ace.inherited === "boolean" &&
          Number.isSafeInteger(ace.rights) &&
          ace.rights >= 0 &&
          ace.rights <= 0xffffffff &&
          (!ace.allow || privileged.has(ace.sid) || !(ace.rights & 0x500d0156)),
      );
    }
    if (possible.has(file.toLowerCase()))
      requireObservation(
        value.security.owner === "S-1-5-18" &&
          value.security.protected === true &&
          value.security.rules.length === 1 &&
          value.security.rules[0].sid === "S-1-5-18" &&
          value.security.rules[0].allow &&
          !value.security.rules[0].inherited &&
          value.security.rules[0].rights === 0x1f01ff,
      );
    return value;
  };
  const hold = async (file, { maximum, signal } = {}, creating = false) => {
    requireObservation(
      canonical(file) &&
        !signal?.aborted &&
        Number.isSafeInteger(maximum) &&
        maximum > 0 &&
        maximum <= PREREQUISITE_FILE_LIMITS.bytes,
    );
    const key = file.toLowerCase(),
      initial = held.get(key);
    requireObservation(!initial?.failed && (creating || !failed.has(key)));
    const before = inspect(
      await call(initial ? "observe" : "hold", file),
      file,
    );
    requireObservation(
      before.bytes <= maximum &&
        (!initial ||
          observationDigest(initial.identity) === observationDigest(before)),
    );
    const chunks = [];
    let offset = 0;
    do {
      requireObservation(!signal?.aborted);
      const count = Math.min(CHUNK_BYTES, before.bytes + 1 - offset);
      const reply = await call("read", file, { offset, count });
      const { data, ...observation } = reply;
      inspect(observation, file);
      requireObservation(
        observationDigest(observation) === observationDigest(before) &&
          typeof data === "string" &&
          data.length <= 65536 &&
          /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(
            data,
          ),
      );
      const bytes = Buffer.from(data, "base64");
      requireObservation(bytes.length <= count);
      chunks.push(bytes);
      offset += bytes.length;
      if (!bytes.length) break;
    } while (offset <= before.bytes);
    const after = inspect(await call("observe", file), file),
      bytes = Buffer.concat(chunks),
      sha256 = digest(bytes);
    requireObservation(
      !signal?.aborted &&
        offset === before.bytes &&
        observationDigest(before) === observationDigest(after) &&
        (!initial || initial.sha256 === sha256),
    );
    held.set(key, { identity: structuredClone(before), sha256, failed: false });
    return {
      file,
      bytes,
      identity: structuredClone(before),
      independent: true,
      held: true,
      protectedParents: true,
      birthProtected: born.has(key),
      unchanged: true,
      readExecuteOnly: true,
      event: { before, after, sha256 },
    };
  };
  const verifyIntent = async (request, intent, signal) => {
    requireObservation(
      intent &&
        inside(intent.file) &&
        intent.file.toLowerCase() !== request.file.toLowerCase() &&
        Number.isSafeInteger(intent.bytes) &&
        intent.bytes > 0 &&
        intent.bytes <= PREREQUISITE_FILE_LIMITS.intentBytes &&
        typeof intent.sha256 === "string" &&
        /^[a-f0-9]{64}$/u.test(intent.sha256),
    );
    const record = await hold(intent.file, { maximum: intent.bytes, signal });
    requireObservation(
      record.bytes.length === intent.bytes &&
        record.event.sha256 === intent.sha256 &&
        record.identity.security.owner === "S-1-5-18" &&
        record.identity.security.protected === true &&
        observationDigest(JSON.parse(record.bytes.toString("utf8"))) ===
          observationDigest(request),
    );
    return record;
  };
  return {
    hold: (file, options) => run(() => hold(file, options)),
    create(file, input, { executable = false, intent, signal } = {}) {
      requireObservation(
        inside(file) &&
          input instanceof Uint8Array &&
          input.length <= PREREQUISITE_FILE_LIMITS.bytes &&
          !held.has(file.toLowerCase()) &&
          !possible.has(file.toLowerCase()),
      );
      const bytes = Buffer.from(input),
        request = prerequisiteCreationRequest(root, file, bytes, executable);
      return run(async () => {
        const record = await verifyIntent(request, intent, signal);
        requireObservation(!signal?.aborted);
        const key = file.toLowerCase();
        requireObservation(!possible.has(key));
        possible.add(key);
        failed.add(key);
        const birth = inspect(await call("create", file), file, "write");
        for (let offset = 0; offset < bytes.length; offset += CHUNK_BYTES) {
          requireObservation(!signal?.aborted);
          const written = inspect(
            await call("write", file, {
              offset,
              data: bytes
                .subarray(offset, offset + CHUNK_BYTES)
                .toString("base64"),
            }),
            file,
            "write",
          );
          requireObservation(
            written.identity === birth.identity &&
              written.bytes === Math.min(offset + CHUNK_BYTES, bytes.length),
          );
        }
        requireObservation(!signal?.aborted);
        const sealed = inspect(await call("seal", file), file);
        requireObservation(sealed.identity === birth.identity);
        try {
          const observed = await hold(
            file,
            { maximum: Math.max(1, bytes.length), signal },
            true,
          );
          requireObservation(
            observationDigest(observed.identity) ===
              observationDigest(sealed) &&
              observed.bytes.length === request.bytes &&
              observed.event.sha256 === request.sha256,
          );
          born.set(key, birth.identity);
          failed.delete(key);
          return {
            ...observed,
            birthProtected: true,
            exclusive: true,
            requestSha256: observationDigest(request),
            intentIdentitySha256: observationDigest(record.identity),
          };
        } catch (error) {
          held.set(key, { failed: true });
          throw error;
        }
      });
    },
    recover(request, { intent, signal } = {}) {
      observationObject(request, [
        "schemaVersion",
        "operation",
        "root",
        "file",
        "bytes",
        "sha256",
        "executable",
      ]);
      requireObservation(
        request?.schemaVersion === 1 &&
          request.operation === "create" &&
          request.root === root &&
          inside(request.file) &&
          Number.isSafeInteger(request.bytes) &&
          request.bytes >= 0 &&
          request.bytes <= PREREQUISITE_FILE_LIMITS.bytes &&
          typeof request.sha256 === "string" &&
          /^[a-f0-9]{64}$/u.test(request.sha256) &&
          typeof request.executable === "boolean",
      );
      request = { ...request };
      return run(async () => {
        await verifyIntent(request, intent, signal);
        possible.add(request.file.toLowerCase());
        failed.add(request.file.toLowerCase());
        requireObservation(!signal?.aborted);
        const observation = inspect(
          await call("hold", request.file),
          request.file,
        );
        return {
          status: "RETAINED",
          requestSha256: observationDigest(request),
          observation,
          birthProtected: false,
          admitted: false,
        };
      });
    },
    async close() {
      fenced = true;
      await pending;
      const result = await call("close", root);
      observationObject(result, [
        "status",
        "closedHandles",
        "custodianRetired",
      ]);
      requireObservation(
        result?.status === "CLOSED" &&
          Number.isSafeInteger(result.closedHandles) &&
          result.closedHandles >= 0 &&
          result.custodianRetired === false,
      );
      return {
        ...result,
        possibleFiles: [...possible],
        uncertainFiles: [...failed],
        custodianRetired: false,
      };
    },
  };
}
