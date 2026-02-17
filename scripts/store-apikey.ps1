# Store API key in Windows Credential Manager using the same format as keytar
# Keytar uses 'OPSIS-Agent:apiKey' as the credential target name
param(
    [string]$ConfigPath
)

$key = $null
try {
    $config = Get-Content $ConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json
    $key = $config.apiKey
} catch {
    exit 0
}

if (-not $key -or $key -eq '') {
    exit 0
}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class CredManager {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredWrite(ref CREDENTIAL cred, uint flags);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredDelete(string target, uint type, uint flags);

    public static bool Store(string target, string userName, string secret) {
        byte[] bytes = System.Text.Encoding.Unicode.GetBytes(secret);
        CREDENTIAL cred = new CREDENTIAL();
        cred.Type = 1; // CRED_TYPE_GENERIC
        cred.TargetName = target;
        cred.UserName = userName;
        cred.Persist = 2; // CRED_PERSIST_LOCAL_MACHINE
        cred.CredentialBlobSize = (uint)bytes.Length;
        cred.CredentialBlob = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, cred.CredentialBlob, bytes.Length);
        bool result = CredWrite(ref cred, 0);
        Marshal.FreeHGlobal(cred.CredentialBlob);
        return result;
    }
}
"@

if ([CredManager]::Store('OPSIS-Agent:apiKey', 'OPSIS-Agent', $key)) {
    Write-Host 'API key stored in Credential Manager'
} else {
    Write-Host 'Failed to store API key'
}
