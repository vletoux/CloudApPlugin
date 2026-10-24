// Ex2.h - the SEC_WINNT_AUTH_IDENTITY_EX2 logon buffer CloudAP's _LsaApLogonUserEx2 routes to a plug-in
// (see the README, "The logon buffer"): User = identity, Domain = the plug-in's registered name,
// PackedCredentials = { CredType GUID, bytes }. Same layout as scripts\Test-Logon.ps1 builds.
#pragma once
#include <windows.h>
#define SECURITY_WIN32
#define _SEC_WINNT_AUTH_TYPES
#include <ntsecapi.h>                                     // UNICODE_STRING, for sspi.h
#include <sspi.h>

// The name CloudApPlugin returns from CloudAPPluginInitialize (record +0x18), equal to its
// IdentityStore\Providers\{guid} Name so that lsasrv also routes "MYCP\user" password logons to it.
#define CLOUDAP_LAB_PROVIDER L"MYCP"

// Builds the buffer with alloc(cb) (CoTaskMemAlloc for LogonUI, anything for a direct LsaLogonUser).
// Returns NULL on overflow or allocation failure.
template <typename Alloc>
static PBYTE BuildEx2(PCWSTR user, PCWSTR domain, const GUID& credType, const void* cred, ULONG cbCred,
    ULONG* cbOut, Alloc alloc)
{
    const ULONG header = 0x30, packedHeader = 0x1C;
    size_t cbUser = wcslen(user) * sizeof(WCHAR), cbDomain = wcslen(domain) * sizeof(WCHAR);
    if (cbUser > 0xFFFF || cbDomain > 0xFFFF || cbCred > 0xFFFF - packedHeader) return NULL;
    ULONG uOff = header, dOff = uOff + (ULONG)cbUser;
    ULONG pOff = (dOff + (ULONG)cbDomain + 3) & ~3u, pLen = packedHeader + cbCred, total = pOff + pLen;
    PBYTE b = (PBYTE)alloc(total);
    if (!b) return NULL;
    ZeroMemory(b, total);
    auto* id = (PSEC_WINNT_AUTH_IDENTITY_EX2)b;
    id->Version = SEC_WINNT_AUTH_IDENTITY_VERSION_2;
    id->cbHeaderLength = (USHORT)header;
    id->cbStructureLength = total;
    id->UserOffset = uOff;
    id->UserLength = (USHORT)cbUser;
    id->DomainOffset = dOff;
    id->DomainLength = (USHORT)cbDomain;
    id->PackedCredentialsOffset = pOff;
    id->PackedCredentialsLength = (USHORT)pLen;
    id->Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    CopyMemory(b + uOff, user, cbUser);
    CopyMemory(b + dOff, domain, cbDomain);
    auto* packed = (PSEC_WINNT_AUTH_PACKED_CREDENTIALS)(b + pOff);
    packed->cbHeaderLength = (USHORT)packedHeader;
    packed->cbStructureLength = (USHORT)pLen;
    packed->AuthData.CredType = credType;
    packed->AuthData.CredData.ByteArrayOffset = packedHeader;
    packed->AuthData.CredData.ByteArrayLength = (USHORT)cbCred;
    CopyMemory(b + pOff + packedHeader, cred, cbCred);
    *cbOut = total;
    return b;
}
