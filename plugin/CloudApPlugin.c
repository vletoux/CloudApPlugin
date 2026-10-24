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
#include <winternl.h>                                          // UNICODE_STRING, for sspi.h
#define SECURITY_WIN32
#define _SEC_WINNT_AUTH_TYPES                                  // SEC_WINNT_AUTH_PACKED_CREDENTIALS + CredType GUIDs
#include <sspi.h>
#include <bcrypt.h>
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

// The plug-in table: { ULONG version; PVOID fn[21]; } (0xB0 bytes), copied into the buffer cloudAP passes
// as the last CloudAPPluginInitialize argument. The slot names are the ones of aadcloudap.dll and
// MicrosoftAccountCloudAP.dll. GetToken (9) and GetKeys (11) are implemented below; the others are
// stubs that log the call and return STATUS_NOT_IMPLEMENTED, except Uninitialize. Never return a
// success without filling the out-parameters: cloudAP would use them inside LSASS.
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

static struct { ULONG version; PVOID fn[21]; } g_pluginTable;
static PVOID* g_cloudAp;                                       // cloudAP's callback table, given at init

// cloudAP's callback [6] = cloudAP!AllocateUserInfo. It builds the APPLUGIN_USER_INFO GetToken returns;
// cloudAP!MakeTokenInformationV2 only reads the SID (+0x10) and the groups (+0x18 count, +0x20 array).
// The name (9th argument, +0x40) is the first field InteractiveLogon reads. aad's
// LoadUserInfoFromCertificate calls it with version 2, the SID, the groups and the name only.
typedef NTSTATUS (NTAPI* ALLOCATE_USER_INFO)(ULONG version, PSID sid, ULONG groupCount, PSID* groups,
    PCWSTR a5, PCWSTR a6, PCWSTR a7, PCWSTR a8, PCWSTR name, PVOID sso, PVOID pwdExpiry, PVOID publicCached,
    ULONG flags, PVOID* userInfo);

// cloudAP's callback [15] = the LSA_SECPKG_FUNCTION_TABLE (+0x28 AllocateLsaHeap). cloudAP frees what
// the plug-in returns (AP_BLOB data, CREDENTIAL_KEY) with FreeLsaHeap.
typedef PVOID (NTAPI* ALLOCATE_LSA_HEAP)(ULONG size);
#define LsaHeapAlloc(cb) (((ALLOCATE_LSA_HEAP*)g_cloudAp[15])[5](cb))

typedef struct _AP_BLOB { ULONG cbSize; PUCHAR pData; } AP_BLOB;

// CREDENTIAL_KEY, as aad's ConstructCredentialKey and cloudAP's BuildCredentialKey lay it out.
typedef struct _CREDENTIAL_KEY {
    ULONG cbTotal;                                             // header + key
    ULONG reserved;
    ULONG cbHeader;                                            // 0x20 = offset of the key
    ULONG cbKey;
    GUID  id;
    BYTE  key[1];
} CREDENTIAL_KEY;
#define CREDENTIAL_KEY_HEADER 0x20
#define CREDENTIAL_KEY_BYTES  0x40

// GetToken's 3rd argument: the EX2 logon buffer after cloudAP!ValidateAuthIdEx2.
typedef struct _DECRYPTED_AUTH_DATA {
    PWSTR userLower;
    PWSTR user;
    PSEC_WINNT_AUTH_PACKED_CREDENTIALS creds;
} DECRYPTED_AUTH_DATA;

// GetToken(ctx, logonType, DECRYPTED_AUTH_DATA*, AP_BLOB* in, AP_BLOB* out, APPLUGIN_USER_INFO** userInfo,
//          SECPKG_SUPPLEMENTAL_CRED_ARRAY** supp). The first slot an interactive logon reaches.
// The EX2 User is mapped to an existing local account. No groups: LSA adds the standard ones. The blob
// returned in "out" is kept by cloudAP in its user cache and given back to GetKeys: the user SID here.
static NTSTATUS NTAPI PluginGetToken(PVOID ctx, ULONG logonType, DECRYPTED_AUTH_DATA* auth, PVOID blobIn, AP_BLOB* blobOut,
    PVOID* userInfo, PVOID* supp)
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
    Log(L"GetToken: logon type %lu, user '%s'", logonType, auth && auth->user ? auth->user : L"(null)");
    if (!auth || !auth->user || !auth->creds || !userInfo) return STATUS_INVALID_PARAMETER;
    *userInfo = NULL;
    if (supp) *supp = NULL;

    creds = auth->creds;
    secret = (PCWSTR)((PBYTE)creds + creds->AuthData.CredData.ByteArrayOffset);
    cbSecret = creds->AuthData.CredData.ByteArrayLength;
    if (!IsEqualGUID(&creds->AuthData.CredType, &SEC_WINNT_AUTH_DATA_TYPE_PASSWORD) ||
        cbSecret != sizeof(LAB_SECRET) - sizeof(WCHAR) || memcmp(secret, LAB_SECRET, cbSecret) != 0)
    {
        Log(L"  credential rejected (type %08lX, %lu bytes)", creds->AuthData.CredType.Data1, cbSecret);
        return STATUS_WRONG_PASSWORD;
    }
    if (!LookupAccountNameW(NULL, auth->user, sid, &cbSid, domain, &cchDomain, &use) || use != SidTypeUser)
    {
        Log(L"  no local account '%s': %lu", auth->user, GetLastError());
        return STATUS_NO_SUCH_USER;
    }
    status = ((ALLOCATE_USER_INFO)g_cloudAp[6])(2, sid, 0, NULL, NULL, NULL, NULL, NULL, auth->user,
        NULL, NULL, NULL, 0, userInfo);
    Log(L"  %s\\%s -> AllocateUserInfo 0x%08lX", domain, auth->user, status);
    if (NT_SUCCESS(status) && blobOut && (blobOut->pData = LsaHeapAlloc(GetLengthSid(sid))) != NULL)
    {
        blobOut->cbSize = GetLengthSid(sid);
        RtlCopyMemory(blobOut->pData, sid, blobOut->cbSize);
    }
    return status;
}

// LAB key: SHA-512("CloudApPlugin LAB DPAPI key" || user SID). Stable across logons, which DPAPI needs,
// but computed from public data. A real plug-in derives it from a secret of the user.
static CREDENTIAL_KEY* MakeLabKey(const AP_BLOB* sid, const GUID* id)
{
    static const char label[] = "CloudApPlugin LAB DPAPI key";
    BYTE input[sizeof(label) + SECURITY_MAX_SID_SIZE];
    CREDENTIAL_KEY* key;
    if (!sid || !sid->pData || sid->cbSize > SECURITY_MAX_SID_SIZE) return NULL;
    key = (CREDENTIAL_KEY*)LsaHeapAlloc(CREDENTIAL_KEY_HEADER + CREDENTIAL_KEY_BYTES);
    if (!key) return NULL;
    RtlZeroMemory(key, CREDENTIAL_KEY_HEADER);
    RtlCopyMemory(input, label, sizeof(label));
    RtlCopyMemory(input + sizeof(label), sid->pData, sid->cbSize);
    if (!BCRYPT_SUCCESS(BCryptHash(BCRYPT_SHA512_ALG_HANDLE, NULL, 0, input, (ULONG)sizeof(label) + sid->cbSize,
        key->key, CREDENTIAL_KEY_BYTES)))
        return NULL;
    key->cbTotal = CREDENTIAL_KEY_HEADER + CREDENTIAL_KEY_BYTES;
    key->cbHeader = CREDENTIAL_KEY_HEADER;
    key->cbKey = CREDENTIAL_KEY_BYTES;
    if (id) key->id = *id; else RtlCopyMemory(&key->id, key->key, sizeof(GUID));
    return key;
}

// GetKeys(ctx, AP_BLOB* ourBlob, GUID*, AP_BLOB*, BOOL, CREDENTIAL_KEY** key, int* needNew,
//         CREDENTIAL_KEY** key2, AP_BLOB* out). Called by cloudAP!GetDPAPIKeys right after GetToken, with
// NULL for the outputs it does not want. When it asks for key2 it also wants a non-empty "out" blob
// (else STATUS_INTERNAL_ERROR), which it saves for the user. The key is recomputed from the SID, so the
// blob only carries the key GUID.
static NTSTATUS NTAPI PluginGetKeys(PVOID ctx, AP_BLOB* blob, GUID* id, AP_BLOB* blob2, BOOL flag,
    CREDENTIAL_KEY** key, int* needNew, CREDENTIAL_KEY** key2, AP_BLOB* out)
{
    UNREFERENCED_PARAMETER(ctx); UNREFERENCED_PARAMETER(blob2);
    Log(L"GetKeys: blob %lu bytes, flag %d, key %p needNew %p key2 %p out %p",
        blob ? blob->cbSize : 0, flag, key, needNew, key2, out);
    if (key && (*key = MakeLabKey(blob, id)) == NULL) return STATUS_NO_MEMORY;
    if (key2 && (*key2 = MakeLabKey(blob, id)) == NULL) return STATUS_NO_MEMORY;
    if (needNew) *needNew = 0;
    if (out)
    {
        out->cbSize = 0;
        if ((out->pData = LsaHeapAlloc(sizeof(GUID))) == NULL) return STATUS_NO_MEMORY;
        RtlCopyMemory(out->pData, key2 ? &(*key2)->id : key ? &(*key)->id : &GUID_NULL, sizeof(GUID));
        out->cbSize = sizeof(GUID);
    }
    return STATUS_SUCCESS;
}

// CloudAPPluginInitialize(version = 1, provider GUID, cloudAP callback table, then out-parameters that
// point into cloudAP's plug-in record): flags (+0xA0), name (+0x18, WCHAR[21]), SID (+0x54, checked
// with RtlValidSid), optional second SID, a pointer left NULL, and the 0xB0-byte buffer of the plug-in
// table, which must be filled in place (storing a pointer there makes cloudAP unload the plug-in).
__declspec(dllexport) NTSTATUS NTAPI CloudAPPluginInitialize(ULONG version, const GUID* provider, PVOID* cloudApTable,
    PULONG outFlags, PWSTR outName, PSID outSid, PVOID* out7, PVOID* out8, PVOID outPluginTable)
{
    static const BYTE providerSid[12] = { 1, 1, 0, 0, 0, 0, 0, 5, 110, 0, 0, 0 };   // S-1-5-110
    WCHAR caller[MAX_PATH + 32];
    Describe(_ReturnAddress(), caller, ARRAYSIZE(caller));
    Log(L"CloudAPPluginInitialize from %s: version %lu, provider {%08lX-...}", caller, version, provider ? provider->Data1 : 0);

    g_pluginTable.version = 1;
#define SETSLOT(idx, nm) g_pluginTable.fn[idx] = (PVOID)&Slot_##nm;
    SLOTS(SETSLOT)
    g_pluginTable.fn[9] = (PVOID)&PluginGetToken;
    g_pluginTable.fn[11] = (PVOID)&PluginGetKeys;
    g_cloudAp = cloudApTable;
    if (outPluginTable) RtlCopyMemory(outPluginTable, &g_pluginTable, sizeof(g_pluginTable));
    if (outFlags) *outFlags = 0;
    if (outName) wcscpy_s(outName, 21, PROVIDER_NAME);
    if (outSid) RtlCopyMemory(outSid, providerSid, sizeof(providerSid));
    if (out7) *out7 = NULL;
    if (out8) *out8 = NULL;
    Log(L"  name %s, plug-in table %p", PROVIDER_NAME, &g_pluginTable);
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
