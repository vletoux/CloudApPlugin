// CloudAp.h - the CloudAP plug-in interface, Windows 11 26100 (cloudAP.dll 10.0.26100.1742).
//
// Nothing here is in the SDK. The function and structure names come from the public symbols of
// cloudAP.dll, aadcloudap.dll and MicrosoftAccountCloudAP.dll: their C++ decorated names give the
// parameter types. The parameter names, and the layouts the symbols do not give, come from the
// disassembly of cloudAP. Where an SDK header already declares the function (ntsecpkg.h for the LSA
// entries), its typedef is used as is.
#pragma once
#include <wincred.h>                                            // before ntsecpkg.h: else the Credi* entries are DummyFunction1..5
#include <ntsecpkg.h>
#include <wincrypt.h>

//
// Opaque types: only pointers to them cross the interface.
//
typedef struct _APPLUGIN_USER_INFO APPLUGIN_USER_INFO, *PAPPLUGIN_USER_INFO;              // built by AllocateUserInfo, 0x88 bytes
typedef struct _APPLUGIN_SSO_USER_INFO APPLUGIN_SSO_USER_INFO, *PAPPLUGIN_SSO_USER_INFO;
typedef struct _APPLUGIN_PWD_EXPIRY_INFO APPLUGIN_PWD_EXPIRY_INFO, *PAPPLUGIN_PWD_EXPIRY_INFO;
typedef struct _APPLUGIN_PUBLIC_CACHED_INFO APPLUGIN_PUBLIC_CACHED_INFO, *PAPPLUGIN_PUBLIC_CACHED_INFO;
typedef struct _LSA_CREDENTIAL_COMPLEXITY LSA_CREDENTIAL_COMPLEXITY, *PLSA_CREDENTIAL_COMPLEXITY;
typedef ULONG UNLOCK_KEY_TYPE;                                  // enum eUnlockKeyType, values not studied

// A buffer the plug-in returns or receives. Allocated on the LSA heap; cloudAP zeroes cbSize bytes
// of pData before FreeLsaHeap.
typedef struct _AP_BLOB {
    ULONG cbSize;
    PUCHAR pData;
} AP_BLOB, *PAP_BLOB;

// The logon credential handed to GetToken, from the SEC_WINNT_AUTH_IDENTITY_EX2 of the logon
// (cloudAP!ValidateAuthIdEx2): the user name, lower-cased and as typed, and the packed credential.
typedef struct _DECRYPTED_AUTH_DATA {
    PWSTR UserLower;
    PWSTR User;
    PSEC_WINNT_AUTH_PACKED_CREDENTIALS Credentials;
} DECRYPTED_AUTH_DATA, *PDECRYPTED_AUTH_DATA;

// The key that protects the user's DPAPI master keys (aad!ConstructCredentialKey,
// cloudAP!BuildCredentialKey). LSA heap, header then key bytes (aad uses 0x40).
typedef struct _CREDENTIAL_KEY {
    ULONG cbTotal;
    ULONG Reserved;
    ULONG cbHeader;                                             // 0x20, offset of Key
    ULONG cbKey;
    GUID  Id;
    UCHAR Key[ANYSIZE_ARRAY];
} CREDENTIAL_KEY, *PCREDENTIAL_KEY;
#define CREDENTIAL_KEY_HEADER_SIZE 0x20

//////////////////////////////////////////////////////////////////////////
//
// CLOUDAP_SECPKG_FUNCTION_TABLE: what cloudAP gives the plug-in.
//
// cloudAP!SpInitialize fills g_CloudAPFunctionTable once, from its own LSA_SECPKG_FUNCTION_TABLE
// (the offset in that table is given for each entry) and from five cloudAP functions. 15 entries,
// 0x78 bytes. What follows it in memory is cloudAP!g_pLsaFunctionTable, a different variable: do
// not read past Generate/VerifyKeyBindingKeyPair.
//
//////////////////////////////////////////////////////////////////////////

// cloudAP!AllocateUserInfo. Builds the user info GetToken / ValidateUserInfo return. The token
// (cloudAP!MakeTokenInformationV2) uses only UserSid and Groups; Name is the first field
// InteractiveLogon reads. aad calls it with Version 2 and only the SID, the groups and Name.
typedef NTSTATUS (CLOUDAP_ALLOCATE_USER_INFO)(
    ULONG Version,                                              // 2
    PSID UserSid,
    ULONG GroupCount,
    PSID* Groups,
    PCWSTR String1,                                             // user info +0x28
    PCWSTR String2,                                             // +0x08
    PCWSTR String3,                                             // +0x30
    PCWSTR String4,                                             // +0x38
    PCWSTR Name,                                                // +0x40
    PAPPLUGIN_SSO_USER_INFO SsoInfo,
    PAPPLUGIN_PWD_EXPIRY_INFO PasswordExpiryInfo,
    PAPPLUGIN_PUBLIC_CACHED_INFO PublicCachedInfo,
    ULONG Flags,                                                // +0x80
    PAPPLUGIN_USER_INFO* UserInfo);

// cloudAP!FreeUserInfo
typedef VOID (CLOUDAP_FREE_USER_INFO)(
    PAPPLUGIN_USER_INFO UserInfo);

// cloudAP!SignMessageWithNgc: signs with a Windows Hello (NGC) key.
typedef NTSTATUS (CLOUDAP_SIGN_MESSAGE_WITH_NGC)(
    PUCHAR KeyBlob,
    USHORT cbKeyBlob,
    HWND Window,
    PUCHAR Message,
    ULONG cbMessage,
    PUCHAR* Signature,
    PULONG cbSignature);

// cloudAP!GenerateKeyBindingKeyPair
typedef NTSTATUS (CLOUDAP_GENERATE_KEY_BINDING_KEY_PAIR)(
    PUCHAR* PublicKey,
    PULONG cbPublicKey,
    PUCHAR* PrivateKey,
    PULONG cbPrivateKey);

// cloudAP!VerifyKeyBindingKeyPair
typedef BOOL (CLOUDAP_VERIFY_KEY_BINDING_KEY_PAIR)(
    PUCHAR PublicKey,
    ULONG cbPublicKey,
    PUCHAR PrivateKey,
    ULONG cbPrivateKey);

typedef struct _CLOUDAP_SECPKG_FUNCTION_TABLE {
    PLSA_IMPERSONATE_CLIENT ImpersonateClient;                  // LSA +0x58
    PLSA_PROTECT_MEMORY LsaProtectMemory;                       // LSA +0x160
    PLSA_PROTECT_MEMORY LsaUnprotectMemory;                     // LSA +0x168
    PLSA_OPEN_TOKEN_BY_LOGON_ID OpenTokenByLogonId;             // LSA +0x170
    PLSA_ALLOCATE_LSA_HEAP AllocateLsaHeap;                     // LSA +0x28
    PLSA_FREE_LSA_HEAP FreeLsaHeap;                             // LSA +0x30
    CLOUDAP_ALLOCATE_USER_INFO* AllocateUserInfo;
    CLOUDAP_FREE_USER_INFO* FreeUserInfo;
    CredReadFn* CrediRead;                                      // LSA +0x148
    CredFreeCredentialsFn* CrediFreeCredentials;                // LSA +0x158
    CredWriteFn* CrediWrite;                                    // LSA +0x198
    CLOUDAP_SIGN_MESSAGE_WITH_NGC* SignMessageWithNgc;
    PLSA_GET_CALL_INFO GetCallInfo;                             // LSA +0xC0
    CLOUDAP_GENERATE_KEY_BINDING_KEY_PAIR* GenerateKeyBindingKeyPair;
    CLOUDAP_VERIFY_KEY_BINDING_KEY_PAIR* VerifyKeyBindingKeyPair;
} CLOUDAP_SECPKG_FUNCTION_TABLE, *PCLOUDAP_SECPKG_FUNCTION_TABLE;

C_ASSERT(sizeof(CLOUDAP_SECPKG_FUNCTION_TABLE) == 0x78);
C_ASSERT(FIELD_OFFSET(LSA_SECPKG_FUNCTION_TABLE, ImpersonateClient) == 0x58);
C_ASSERT(FIELD_OFFSET(LSA_SECPKG_FUNCTION_TABLE, AllocateLsaHeap) == 0x28);
C_ASSERT(FIELD_OFFSET(LSA_SECPKG_FUNCTION_TABLE, FreeLsaHeap) == 0x30);
C_ASSERT(FIELD_OFFSET(LSA_SECPKG_FUNCTION_TABLE, GetCallInfo) == 0xC0);
C_ASSERT(FIELD_OFFSET(LSA_SECPKG_FUNCTION_TABLE, CrediRead) == 0x148);
C_ASSERT(FIELD_OFFSET(LSA_SECPKG_FUNCTION_TABLE, CrediFreeCredentials) == 0x158);
C_ASSERT(FIELD_OFFSET(LSA_SECPKG_FUNCTION_TABLE, LsaProtectMemory) == 0x160);
C_ASSERT(FIELD_OFFSET(LSA_SECPKG_FUNCTION_TABLE, LsaUnprotectMemory) == 0x168);
C_ASSERT(FIELD_OFFSET(LSA_SECPKG_FUNCTION_TABLE, OpenTokenByLogonId) == 0x170);
C_ASSERT(FIELD_OFFSET(LSA_SECPKG_FUNCTION_TABLE, CrediWrite) == 0x198);

//////////////////////////////////////////////////////////////////////////
//
// APPLUGIN_SECPKG_FUNCTION_TABLE: what the plug-in gives cloudAP.
//
// The Microsoft plug-ins build it from two static tables, g_*NoNetworkFunctionTable (9 entries,
// usable without network) and g_*NetworkOkFunctionTable (12 entries). Prototypes from the symbols
// of the aad and MSA functions; Context is the value the plug-in returned from
// CloudAPPluginInitialize. A NULL entry is allowed for most slots: cloudAP tests the pointer first.
//
//////////////////////////////////////////////////////////////////////////

typedef NTSTATUS (APPLUGIN_UNINITIALIZE)(PVOID Context);

// A user already in cloudAP's cache logs on again: same outputs as GetToken, from the saved blob.
typedef NTSTATUS (APPLUGIN_VALIDATE_USER_INFO)(PVOID Context, GUID* ProviderGuid, PAP_BLOB TokenBlob,
    PAPPLUGIN_USER_INFO* UserInfo, PINT Arg5, PINT Arg6, PSECPKG_SUPPLEMENTAL_CRED_ARRAY* Supplemental);

typedef NTSTATUS (APPLUGIN_GET_UNLOCK_KEY)(PVOID Context, PSEC_WINNT_AUTH_PACKED_CREDENTIALS Credentials,
    UNLOCK_KEY_TYPE* KeyType, PAP_BLOB Key);

// Slot 3. NULL in both Microsoft plug-ins. Called by cloudAP!SyncDpapiKey when a flag of the user
// cache asks for it, with the same second argument as UserProfileLoaded and the GetToken blob.
typedef NTSTATUS (APPLUGIN_SLOT3)(PVOID Context, PVOID Arg2, PAP_BLOB TokenBlob);

typedef NTSTATUS (APPLUGIN_GET_DEFAULT_CREDENTIAL_COMPLEXITY)(PVOID Context, PLSA_CREDENTIAL_COMPLEXITY Complexity);

typedef NTSTATUS (APPLUGIN_IS_CONNECTED)(PVOID Context, PVOID Arg2, PINT Connected);

// PKU2U: the user info of a peer certificate.
typedef NTSTATUS (APPLUGIN_ACCEPT_PEER_CERTIFICATE)(PVOID Context, INT Flags, PCCERT_CONTEXT Certificate,
    PAPPLUGIN_USER_INFO* UserInfo);

typedef NTSTATUS (APPLUGIN_ASSEMBLE_OPAQUE_DATA)(PVOID Context, PAP_BLOB In1, PAP_BLOB In2, PAP_BLOB Out);
typedef NTSTATUS (APPLUGIN_DISASSEMBLE_OPAQUE_DATA)(PVOID Context, PAP_BLOB In, PAP_BLOB Out1, PAP_BLOB Out2);

// Interactive logon: the first slot called. TokenBlobOut (LSA heap) is kept in cloudAP's user cache
// and given back to GetKeys, ValidateUserInfo, UserProfileLoaded...
typedef NTSTATUS (APPLUGIN_GET_TOKEN)(PVOID Context, SECURITY_LOGON_TYPE LogonType, PDECRYPTED_AUTH_DATA AuthData,
    PAP_BLOB TokenBlobIn, PAP_BLOB TokenBlobOut, PAPPLUGIN_USER_INFO* UserInfo,
    PSECPKG_SUPPLEMENTAL_CRED_ARRAY* Supplemental);

typedef NTSTATUS (APPLUGIN_REFRESH_TOKEN)(PVOID Context, PAP_BLOB TokenBlobIn, PAP_BLOB TokenBlobOut,
    PUCHAR* Data, PULONG cbData, PSECPKG_SUPPLEMENTAL_CRED_ARRAY* Supplemental);

// cloudAP!GetDPAPIKeys, right after GetToken. NULL for the outputs cloudAP does not want; when it
// asks for Key2, KeyBlob must not come back empty (else STATUS_INTERNAL_ERROR).
typedef NTSTATUS (APPLUGIN_GET_KEYS)(PVOID Context, PAP_BLOB TokenBlob, GUID* KeyId, PAP_BLOB SavedKeyBlob,
    INT Flag, PCREDENTIAL_KEY* Key, PINT NeedNewKey, PCREDENTIAL_KEY* Key2, PAP_BLOB KeyBlob);

typedef NTSTATUS (APPLUGIN_LOOKUP_SID_FROM_IDENTITY_NAME)(PVOID Context, PVOID Arg2, PWSTR IdentityName,
    PSID* Sid, PWSTR* Out1, PWSTR* Out2, PWSTR* Out3, PWSTR* Out4, PWSTR* Out5, PWSTR* Out6);

typedef NTSTATUS (APPLUGIN_LOOKUP_IDENTITY_FROM_SID_NAME)(PVOID Context, PVOID Arg2, PSID Sid,
    PWSTR* Out1, PWSTR* Out2, PWSTR* Out3, PWSTR* Out4, PWSTR* Out5, PWSTR* Out6, PWSTR* Out7);

typedef NTSTATUS (APPLUGIN_USER_PROFILE_LOADED)(PVOID Context, PVOID Arg2, PAP_BLOB TokenBlob, INT Flag);

typedef NTSTATUS (APPLUGIN_CONNECT_IDENTITY)(PVOID Context, INT Flag, PVOID Arg3, PVOID Arg4, PAP_BLOB Blob);

typedef NTSTATUS (APPLUGIN_DISCONNECT_IDENTITY)(PVOID Context, PVOID Arg2, PVOID Arg3, PAP_BLOB Blob);

typedef NTSTATUS (APPLUGIN_RENEW_CERTIFICATE)(PVOID Context, PAP_BLOB TokenBlob, INT Flag);

typedef NTSTATUS (APPLUGIN_GET_CERTIFICATE_FROM_CRED)(PVOID Context, PLUID LogonId, PDECRYPTED_AUTH_DATA AuthData,
    PVOID* Certificate);

// LsaCallAuthenticationPackage(CloudAP) messages addressed to the plug-in.
typedef NTSTATUS (APPLUGIN_GENERIC_CALL_PKG)(PVOID Context, PVOID Arg2, PAP_BLOB Input, PAP_BLOB Output1, PAP_BLOB Output2);

typedef NTSTATUS (APPLUGIN_POST_LOGON_PROCESSING)(PVOID Context, PVOID Arg2, PAP_BLOB TokenBlob, PAP_BLOB Out);

typedef struct _APPLUGIN_NO_NETWORK_FUNCTIONS {
    APPLUGIN_UNINITIALIZE* PluginUninitialize;                  // 0
    APPLUGIN_VALIDATE_USER_INFO* ValidateUserInfo;              // 1
    APPLUGIN_GET_UNLOCK_KEY* GetUnlockKey;                      // 2
    APPLUGIN_SLOT3* Slot3;                                      // 3
    APPLUGIN_GET_DEFAULT_CREDENTIAL_COMPLEXITY* GetDefaultCredentialComplexity; // 4
    APPLUGIN_IS_CONNECTED* IsConnected;                         // 5
    APPLUGIN_ACCEPT_PEER_CERTIFICATE* AcceptPeerCertificate;    // 6
    APPLUGIN_ASSEMBLE_OPAQUE_DATA* AssembleOpaqueData;          // 7
    APPLUGIN_DISASSEMBLE_OPAQUE_DATA* DisassembleOpaqueData;    // 8
} APPLUGIN_NO_NETWORK_FUNCTIONS;

typedef struct _APPLUGIN_NETWORK_OK_FUNCTIONS {
    APPLUGIN_GET_TOKEN* PluginGetToken;                         // 9
    APPLUGIN_REFRESH_TOKEN* RefreshToken;                       // 10
    APPLUGIN_GET_KEYS* PluginGetKeys;                           // 11
    APPLUGIN_LOOKUP_SID_FROM_IDENTITY_NAME* LookupSIDFromIdentityName; // 12
    APPLUGIN_LOOKUP_IDENTITY_FROM_SID_NAME* LookupIdentityFromSIDName; // 13
    APPLUGIN_USER_PROFILE_LOADED* UserProfileLoaded;            // 14
    APPLUGIN_CONNECT_IDENTITY* ConnectIdentity;                 // 15
    APPLUGIN_DISCONNECT_IDENTITY* DisconnectIdentity;           // 16
    APPLUGIN_RENEW_CERTIFICATE* RenewCertificate;               // 17
    APPLUGIN_GET_CERTIFICATE_FROM_CRED* GetCertificateFromCred; // 18
    APPLUGIN_GENERIC_CALL_PKG* GenericCallPkg;                  // 19
    APPLUGIN_POST_LOGON_PROCESSING* PostLogonProcessing;        // 20
} APPLUGIN_NETWORK_OK_FUNCTIONS;

typedef struct _APPLUGIN_SECPKG_FUNCTION_TABLE {
    ULONG Version;                                              // 1
    APPLUGIN_NO_NETWORK_FUNCTIONS NoNetwork;
    APPLUGIN_NETWORK_OK_FUNCTIONS NetworkOk;
} APPLUGIN_SECPKG_FUNCTION_TABLE, *PAPPLUGIN_SECPKG_FUNCTION_TABLE;

C_ASSERT(sizeof(APPLUGIN_SECPKG_FUNCTION_TABLE) == 0xB0);
C_ASSERT(FIELD_OFFSET(APPLUGIN_SECPKG_FUNCTION_TABLE, NetworkOk.PluginGetToken) == 0x50);
C_ASSERT(FIELD_OFFSET(APPLUGIN_SECPKG_FUNCTION_TABLE, NetworkOk.PluginGetKeys) == 0x60);

//////////////////////////////////////////////////////////////////////////
//
// The export. Prototype of aad!CloudAPPluginInitialize; every out-parameter points into the
// 0x188-byte record cloudAP!LoadPlugin keeps for the plug-in.
//
//////////////////////////////////////////////////////////////////////////

// Flags bits seen in cloudAP: 0x01 skips the DPAPI key sync (SyncDpapiKey), 0x04 is required to be
// chosen by the surrogate for a smart card logon, 0x10 marks the default plug-in (RefDefaultPackage).
typedef NTSTATUS (CLOUDAP_PLUGIN_INITIALIZE)(
    ULONG Version,                                              // 1
    GUID* ProviderGuid,
    PCLOUDAP_SECPKG_FUNCTION_TABLE CloudApFunctions,
    PULONG Flags,                                               // out, record +0xA0
    PWSTR Name,                                                 // out, WCHAR[21] at record +0x18
    PUCHAR Sid,                                                 // out, SID buffer at record +0x54, RtlValidSid
    PVOID* Sid2,                                                // out, optional, RtlValidSid when set
    PVOID* Context,                                             // out, record +0x08, first argument of every slot
    PAPPLUGIN_SECPKG_FUNCTION_TABLE PluginFunctions);           // out, 0xB0 bytes filled in place
