# Remove all OPSIS Agent credentials from Windows Credential Manager
# Handles both cmdkey-style and keytar-style (colon separator) entries

# Remove cmdkey-style entries (legacy)
cmdkey /delete:OPSISAgent_ApiKey 2>$null
cmdkey /delete:OPSIS-Agent/apiKey 2>$null
cmdkey /delete:OPSIS-Agent/hmacSecret 2>$null
cmdkey /delete:OPSIS-Agent/ipcSecret 2>$null
cmdkey /delete:OPSIS-Agent/runbookIntegrityManifest 2>$null

# Remove keytar-style entries (colon separator) via Win32 API
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class CredDel {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredDelete(string target, uint type, uint flags);
}
"@

[CredDel]::CredDelete('OPSIS-Agent:apiKey', 1, 0) | Out-Null
[CredDel]::CredDelete('OPSIS-Agent:hmacSecret', 1, 0) | Out-Null
[CredDel]::CredDelete('OPSIS-Agent:ipcSecret', 1, 0) | Out-Null
[CredDel]::CredDelete('OPSIS-Agent:runbookIntegrityManifest', 1, 0) | Out-Null
