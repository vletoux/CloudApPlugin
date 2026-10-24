// CloudApPlugin - a third-party CloudAP plug-in, as Windows 11 26100 calls it.
//
// cloudAP!InitializePlugins enumerates HKLM\SOFTWARE\Microsoft\IdentityStore\Providers\{guid}. For a GUID
// other than its own (Azure AD, Microsoft account), cloudAP!LoadPlugin wants:
//   IdentityStore\LoadParameters\{guid}\Enabled != 0 (else 0xC00002E9),
//   Providers\{guid}\ApPluginDLLPath, loaded with LoadLibraryExW(0x880 = SEARCH_SYSTEM32 | REQUIRE_SIGNED_TARGET),
//   the export CloudAPPluginInitialize, which fills cloudAP's 0x188-byte plug-in record.
// REQUIRE_SIGNED_TARGET means a Microsoft signature: an unsigned DLL, or one signed by your own CA, is
// refused with error 577, LSA protection on or off. See the README.
//
// A logon reaches the plug-in when it is submitted to the CloudAP package as a SEC_WINNT_AUTH_IDENTITY_EX2
// whose Domain is the plug-in name (cloudAP!_LsaApLogonUserEx2), or as a Negotiate password logon
// "<name>\user" that lsasrv rewrites into that EX2. Interactive logon calls GetToken, then GetKeys.
//
// Everything is logged in C:\Windows\Temp\CloudApPlugin.txt.
#ifndef UNICODE
#define UNICODE
#endif
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <ntsecapi.h>                                           // UNICODE_STRING, for sspi.h
#define SECURITY_WIN32
#define _SEC_WINNT_AUTH_TYPES                                  // SEC_WINNT_AUTH_PACKED_CREDENTIALS + CredType GUIDs
#include <sspi.h>
#include <bcrypt.h>
#ifndef NT_SUCCESS
#define NT_SUCCESS(status) ((NTSTATUS)(status) >= 0)
#endif
#include "CloudAp.h"
#include <stdio.h>
#include <intrin.h>

// The name returned to cloudAP (record +0x18, at most 20 characters). It must be the Name value of the
// IdentityStore\Providers\{guid} key: lsasrv finds the provider by that name, cloudAP finds the plug-in
// by this one, and both are compared with the Domain of the logon.
#define PROVIDER_NAME L"MYCP"

// LAB: the secret GetToken accepts. Replace it with a real check (a card signature, a token from your IdP).
#define LAB_SECRET L"123456"

static SRWLOCK g_logLock = SRWLOCK_INIT;

static void Log(PCWSTR format, ...)
{
    FILE* f;
    va_list args;
    SYSTEMTIME now;
    AcquireSRWLockExclusive(&g_logLock);
    if (_wfopen_s(&f, L"C:\\Windows\\Temp\\CloudApPlugin.txt", L"a, ccs=UTF-8") == 0)
    {
        GetLocalTime(&now);
        fwprintf(f, L"%02u:%02u:%02u.%03u [%lu] ", now.wHour, now.wMinute, now.wSecond, now.wMilliseconds, GetCurrentProcessId());
        va_start(args, format);
        vfwprintf(f, format, args);
        va_end(args);
        fwprintf(f, L"\n");
        fclose(f);
    }
    ReleaseSRWLockExclusive(&g_logLock);
}

// "module+0xoffset" of an address, or the raw value when it is in no module.
static void Describe(PVOID address, PWSTR text, SIZE_T cch)
{
    HMODULE module;
    WCHAR path[MAX_PATH];
    PCWSTR name;
    if (address && GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (PCWSTR)address, &module)
        && GetModuleFileNameW(module, path, ARRAYSIZE(path)))
    {
        name = wcsrchr(path, L'\\');
        swprintf_s(text, cch, L"%s+0x%Ix", name ? name + 1 : path, (ULONG_PTR)address - (ULONG_PTR)module);
    }
    else
        swprintf_s(text, cch, L"%p", address);
}

// The plug-in table (APPLUGIN_SECPKG_FUNCTION_TABLE, CloudAp.h) is copied into the buffer cloudAP
// passes as the last CloudAPPluginInitialize argument. GetToken (9) and GetKeys (11) are implemented
// below; the others are stubs that log the call and return STATUS_NOT_IMPLEMENTED, except
// Uninitialize. Never return a success without filling the out-parameters: cloudAP would use them
// inside LSASS. A stub is not a NULL slot: cloudAP skips most NULL slots, but takes a stub's error
// as a failure (SyncDpapiKey for slots 3 and 14).
#define SLOTS(X) \
    X( 0, Uninitialize)              X( 1, ValidateUserInfo)   X( 2, GetUnlockKey) \
    X( 3, Slot3)                     X( 4, GetDefaultCredComplexity) X( 5, IsConnected) \
    X( 6, AcceptPeerCertificate)     X( 7, AssembleOpaqueData) X( 8, DisassembleOpaqueData) \
    X( 9, GetToken)                  X(10, RefreshToken)       X(11, GetKeys) \
    X(12, LookupSIDFromIdentityName) X(13, LookupIdentityFromSIDName) X(14, UserProfileLoaded) \
    X(15, ConnectIdentity)           X(16, DisconnectIdentity) X(17, RenewCertificate) \
    X(18, GetCertificateFromCred)    X(19, GenericCallPkg)     X(20, PostLogonProcessing)

#define DEFSTUB(idx, nm) \
    static NTSTATUS NTAPI Slot_##nm(PVOID a1, PVOID a2, PVOID a3, PVOID a4, PVOID a5, PVOID a6, PVOID a7, PVOID a8, PVOID a9) { \
        WCHAR who[MAX_PATH + 32]; \
        UNREFERENCED_PARAMETER(a8); UNREFERENCED_PARAMETER(a9); \
        Describe(_ReturnAddress(), who, ARRAYSIZE(who)); \
        Log(L"slot %2u " L#nm L" from %s: args %p %p %p %p %p %p %p", idx, who, a1, a2, a3, a4, a5, a6, a7); \
        return idx == 0 ? STATUS_SUCCESS : STATUS_NOT_IMPLEMENTED; \
    }
SLOTS(DEFSTUB)

static PCLOUDAP_SECPKG_FUNCTION_TABLE g_cloudAp;               // cloudAP's callbacks, given at init

// What the plug-in returns (AP_BLOB data, CREDENTIAL_KEY) is freed by cloudAP with FreeLsaHeap.
#define LsaHeapAlloc(cb) g_cloudAp->AllocateLsaHeap(cb)
#define CREDENTIAL_KEY_BYTES 0x40                              // as aad

// The first slot an interactive logon reaches. The EX2 User is mapped to an existing local account,
// no groups (LSA adds the standard ones). The user info comes from cloudAP's AllocateUserInfo, called
// like aad's LoadUserInfoFromCertificate does. The blob returned in blobOut is kept by cloudAP in its
// user cache and given back to GetKeys: the user SID here.
static NTSTATUS PluginGetToken(PVOID ctx, SECURITY_LOGON_TYPE logonType, PDECRYPTED_AUTH_DATA auth, PAP_BLOB blobIn,
    PAP_BLOB blobOut, PAPPLUGIN_USER_INFO* userInfo, PSECPKG_SUPPLEMENTAL_CRED_ARRAY* supp)
{
    WCHAR domain[MAX_PATH];
    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD cbSid = sizeof(sid), cchDomain = ARRAYSIZE(domain);
    SID_NAME_USE use;
    PSEC_WINNT_AUTH_PACKED_CREDENTIALS creds;
    PCWSTR secret;
    ULONG cbSecret;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(ctx); UNREFERENCED_PARAMETER(blobIn);
    Log(L"GetToken: logon type %d, user '%s'", logonType, auth && auth->User ? auth->User : L"(null)");
    if (!auth || !auth->User || !auth->Credentials || !userInfo) return STATUS_INVALID_PARAMETER;
    *userInfo = NULL;
    if (supp) *supp = NULL;

    creds = auth->Credentials;
    secret = (PCWSTR)((PBYTE)creds + creds->AuthData.CredData.ByteArrayOffset);
    cbSecret = creds->AuthData.CredData.ByteArrayLength;
    if (!IsEqualGUID(&creds->AuthData.CredType, &SEC_WINNT_AUTH_DATA_TYPE_PASSWORD) ||
        cbSecret != sizeof(LAB_SECRET) - sizeof(WCHAR) || memcmp(secret, LAB_SECRET, cbSecret) != 0)
    {
        Log(L"  credential rejected (type %08lX, %lu bytes)", creds->AuthData.CredType.Data1, cbSecret);
        return STATUS_WRONG_PASSWORD;
    }
    if (!LookupAccountNameW(NULL, auth->User, sid, &cbSid, domain, &cchDomain, &use) || use != SidTypeUser)
    {
        Log(L"  no local account '%s': %lu", auth->User, GetLastError());
        return STATUS_NO_SUCH_USER;
    }
    status = g_cloudAp->AllocateUserInfo(2, sid, 0, NULL, NULL, NULL, NULL, NULL, auth->User, NULL, NULL, NULL, 0, userInfo);
    Log(L"  %s\\%s -> AllocateUserInfo 0x%08lX", domain, auth->User, status);
    if (NT_SUCCESS(status) && blobOut && (blobOut->pData = LsaHeapAlloc(GetLengthSid(sid))) != NULL)
    {
        blobOut->cbSize = GetLengthSid(sid);
        RtlCopyMemory(blobOut->pData, sid, blobOut->cbSize);
    }
    return status;
}

// LAB key: SHA-512("CloudApPlugin LAB DPAPI key" || user SID). Stable across logons, which DPAPI needs,
// but computed from public data. A real plug-in derives it from a secret of the user.
static PCREDENTIAL_KEY MakeLabKey(const AP_BLOB* sid, const GUID* id)
{
    static const char label[] = "CloudApPlugin LAB DPAPI key";
    BYTE input[sizeof(label) + SECURITY_MAX_SID_SIZE];
    PCREDENTIAL_KEY key;
    if (!sid || !sid->pData || sid->cbSize > SECURITY_MAX_SID_SIZE) return NULL;
    key = (PCREDENTIAL_KEY)LsaHeapAlloc(CREDENTIAL_KEY_HEADER_SIZE + CREDENTIAL_KEY_BYTES);
    if (!key) return NULL;
    RtlZeroMemory(key, CREDENTIAL_KEY_HEADER_SIZE);
    RtlCopyMemory(input, label, sizeof(label));
    RtlCopyMemory(input + sizeof(label), sid->pData, sid->cbSize);
    if (!BCRYPT_SUCCESS(BCryptHash(BCRYPT_SHA512_ALG_HANDLE, NULL, 0, input, (ULONG)sizeof(label) + sid->cbSize,
        key->Key, CREDENTIAL_KEY_BYTES)))
        return NULL;
    key->cbTotal = CREDENTIAL_KEY_HEADER_SIZE + CREDENTIAL_KEY_BYTES;
    key->cbHeader = CREDENTIAL_KEY_HEADER_SIZE;
    key->cbKey = CREDENTIAL_KEY_BYTES;
    if (id) key->Id = *id; else RtlCopyMemory(&key->Id, key->Key, sizeof(GUID));
    return key;
}

// Called by cloudAP!GetDPAPIKeys right after GetToken, with NULL for the outputs it does not want.
// When it asks for key2 it also wants a non-empty keyBlob (else STATUS_INTERNAL_ERROR), which it saves
// for the user. The key is recomputed from the SID, so the blob only carries the key GUID.
static NTSTATUS PluginGetKeys(PVOID ctx, PAP_BLOB blob, GUID* id, PAP_BLOB savedKeyBlob, INT flag,
    PCREDENTIAL_KEY* key, PINT needNew, PCREDENTIAL_KEY* key2, PAP_BLOB keyBlob)
{
    UNREFERENCED_PARAMETER(ctx); UNREFERENCED_PARAMETER(savedKeyBlob);
    Log(L"GetKeys: blob %lu bytes, flag %d, key %p needNew %p key2 %p keyBlob %p",
        blob ? blob->cbSize : 0, flag, key, needNew, key2, keyBlob);
    if (key && (*key = MakeLabKey(blob, id)) == NULL) return STATUS_NO_MEMORY;
    if (key2 && (*key2 = MakeLabKey(blob, id)) == NULL) return STATUS_NO_MEMORY;
    if (needNew) *needNew = 0;
    if (keyBlob)
    {
        keyBlob->cbSize = 0;
        if ((keyBlob->pData = LsaHeapAlloc(sizeof(GUID))) == NULL) return STATUS_NO_MEMORY;
        RtlCopyMemory(keyBlob->pData, key2 ? &(*key2)->Id : key ? &(*key)->Id : &GUID_NULL, sizeof(GUID));
        keyBlob->cbSize = sizeof(GUID);
    }
    return STATUS_SUCCESS;
}

// The stubs share one signature: cast to the slot type.
#define STUB(nm, type) (type*)&Slot_##nm
static const APPLUGIN_SECPKG_FUNCTION_TABLE g_pluginTable = {
    1,
    {
        STUB(Uninitialize, APPLUGIN_UNINITIALIZE),
        STUB(ValidateUserInfo, APPLUGIN_VALIDATE_USER_INFO),
        STUB(GetUnlockKey, APPLUGIN_GET_UNLOCK_KEY),
        STUB(Slot3, APPLUGIN_SLOT3),
        STUB(GetDefaultCredComplexity, APPLUGIN_GET_DEFAULT_CREDENTIAL_COMPLEXITY),
        STUB(IsConnected, APPLUGIN_IS_CONNECTED),
        STUB(AcceptPeerCertificate, APPLUGIN_ACCEPT_PEER_CERTIFICATE),
        STUB(AssembleOpaqueData, APPLUGIN_ASSEMBLE_OPAQUE_DATA),
        STUB(DisassembleOpaqueData, APPLUGIN_DISASSEMBLE_OPAQUE_DATA),
    },
    {
        PluginGetToken,
        STUB(RefreshToken, APPLUGIN_REFRESH_TOKEN),
        PluginGetKeys,
        STUB(LookupSIDFromIdentityName, APPLUGIN_LOOKUP_SID_FROM_IDENTITY_NAME),
        STUB(LookupIdentityFromSIDName, APPLUGIN_LOOKUP_IDENTITY_FROM_SID_NAME),
        STUB(UserProfileLoaded, APPLUGIN_USER_PROFILE_LOADED),
        STUB(ConnectIdentity, APPLUGIN_CONNECT_IDENTITY),
        STUB(DisconnectIdentity, APPLUGIN_DISCONNECT_IDENTITY),
        STUB(RenewCertificate, APPLUGIN_RENEW_CERTIFICATE),
        STUB(GetCertificateFromCred, APPLUGIN_GET_CERTIFICATE_FROM_CRED),
        STUB(GenericCallPkg, APPLUGIN_GENERIC_CALL_PKG),
        STUB(PostLogonProcessing, APPLUGIN_POST_LOGON_PROCESSING),
    },
};

// The export (CLOUDAP_PLUGIN_INITIALIZE in CloudAp.h). The out-parameters point into cloudAP's
// plug-in record; the plug-in table must be copied into the buffer cloudAP passes (storing a
// pointer there makes cloudAP unload the plug-in). No context: the slots get NULL.
__declspec(dllexport) NTSTATUS CloudAPPluginInitialize(ULONG version, GUID* provider, PCLOUDAP_SECPKG_FUNCTION_TABLE cloudApFunctions,
    PULONG flags, PWSTR name, PUCHAR sid, PVOID* sid2, PVOID* context, PAPPLUGIN_SECPKG_FUNCTION_TABLE pluginFunctions)
{
    static const BYTE providerSid[12] = { 1, 1, 0, 0, 0, 0, 0, 5, 110, 0, 0, 0 };   // S-1-5-110
    static CLOUDAP_PLUGIN_INITIALIZE* const checkType = CloudAPPluginInitialize;
    WCHAR caller[MAX_PATH + 32];
    UNREFERENCED_PARAMETER(checkType);
    Describe(_ReturnAddress(), caller, ARRAYSIZE(caller));
    Log(L"CloudAPPluginInitialize from %s: version %lu, provider {%08lX-...}", caller, version, provider ? provider->Data1 : 0);

    g_cloudAp = cloudApFunctions;
    if (pluginFunctions) *pluginFunctions = g_pluginTable;
    if (flags) *flags = 0;
    if (name) wcscpy_s(name, 21, PROVIDER_NAME);
    if (sid) RtlCopyMemory(sid, providerSid, sizeof(providerSid));
    if (sid2) *sid2 = NULL;
    if (context) *context = NULL;
    Log(L"  name %s", PROVIDER_NAME);
    return STATUS_SUCCESS;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, PVOID reserved)
{
    WCHAR process[MAX_PATH];
    UNREFERENCED_PARAMETER(instance);
    UNREFERENCED_PARAMETER(reserved);
    if (reason == DLL_PROCESS_ATTACH)
    {
        GetModuleFileNameW(NULL, process, ARRAYSIZE(process));
        Log(L"loaded in %s", process);
    }
    else if (reason == DLL_PROCESS_DETACH)
        Log(L"unloaded");
    return TRUE;
}
