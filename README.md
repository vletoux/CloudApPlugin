# CloudApPlugin

A third-party CloudAP plug-in, and the contract it implements.

CloudAP is the Windows authentication package behind Entra ID (Azure AD) and Microsoft account
logons. It does not talk to the cloud itself: it loads plug-ins, `aadcloudap.dll` and
`MicrosoftAccountCloudAP.dll`, and asks them for the token. The plug-in interface is not
documented and there is no SDK. I wanted to know what a plug-in for another identity provider
would need, so I worked out the contract from `cloudAP.dll` (Windows 11 26100, public symbols) and
the two Microsoft plug-ins, then wrote one that implements it.

This repository contains:

- `plugin\` - the plug-in, `CloudApPlugin.dll`. It logs a local account on, interactively, with a
  secret checked by the plug-in. The logon session belongs to CloudAP, like an Entra ID logon.
- `credprov\` - a minimal credential provider, `CloudApCp.dll`, that sends a logon to the plug-in
  from the logon screen and the lock screen.
- `scripts\` - registration and a test logon without UI.

The full write-up is here:
https://www.mysmartlogon.com/service/cloudap-third-party-plugin/

> **Read this first.** CloudAP loads plug-ins with `LOAD_LIBRARY_REQUIRE_SIGNED_TARGET`: only a DLL
> signed by Microsoft is accepted. Your own Authenticode signature is not enough, and LSA protection
> has nothing to do with it. So on a normal Windows this plug-in is **not** loaded: `LoadLibraryExW`
> fails with error 577 and `C:\Windows\Temp\CloudApPlugin.txt` stays empty. I could test it only in a lab VM where
> that check was relaxed; that part is not published. Treat this repository as documentation of the
> interface with working code, not as something you can install today.
>
> The plug-in is also a test: it accepts one fixed secret (`123456`) and derives the DPAPI key from
> the user SID. Lab VM only.

## How CloudAP loads a plug-in

At start (and on call-package message 0, see `scripts\Reinit-Plugins.ps1`), `cloudAP!InitializePlugins`
enumerates `HKLM\SOFTWARE\Microsoft\IdentityStore\Providers\{guid}`. For each provider other than
its own two, `cloudAP!LoadPlugin` wants:

```
HKLM\SOFTWARE\Microsoft\IdentityStore\Providers\{5A0C2E62-7D4B-4C1A-9F3E-2B8D6E1A4C70}
    Name             REG_SZ        MYCP
    ApPluginDLLPath  REG_EXPAND_SZ %SystemRoot%\System32\CloudApPlugin.dll
HKLM\SOFTWARE\Microsoft\IdentityStore\LoadParameters\{5A0C2E62-7D4B-4C1A-9F3E-2B8D6E1A4C70}
    Enabled          REG_DWORD     1
```

Without `Enabled` it fails with `0xC00002E9`. Then `LoadLibraryExW(path, 0, 0x880)` (search
System32, require a signed target) and `GetProcAddress("CloudAPPluginInitialize")`. The `Providers`
key belongs to TrustedInstaller, even SYSTEM cannot write it; `scripts\Provider.ps1` opens it with
`REG_OPTION_BACKUP_RESTORE` and `SeRestorePrivilege` instead of changing its ACL.

The provider GUID must not be registered by anything else as an LSA identity provider: after the
plug-in initializes, cloudAP registers the GUID with LSA, and a duplicate makes `LoadPlugin` fail
with `0xC0000718` and unload the plug-in.

## CloudAPPluginInitialize

All the types are in [`plugin\CloudAp.h`](plugin/CloudAp.h). The prototype is the one of
`aadcloudap!CloudAPPluginInitialize` (its public symbol is a C++ decorated name, so it carries the
parameter types and the structure names):

```c
NTSTATUS CloudAPPluginInitialize(
    ULONG Version,                                     // 1
    GUID* ProviderGuid,
    PCLOUDAP_SECPKG_FUNCTION_TABLE CloudApFunctions,   // what cloudAP gives the plug-in
    PULONG Flags,                                      // out
    PWSTR Name,                                        // out, WCHAR[21]
    PUCHAR Sid,                                        // out, SID buffer, must pass RtlValidSid
    PVOID* Sid2,                                       // out, optional
    PVOID* Context,                                    // out, first argument of every plug-in function
    PAPPLUGIN_SECPKG_FUNCTION_TABLE PluginFunctions);  // out, 0xB0 bytes to FILL, not a pointer to store
```

All the out-parameters point into the 0x188-byte record cloudAP keeps for the plug-in. The last one
is the easy mistake: cloudAP passes a buffer and the plug-in copies its table into it. Storing a
pointer there makes cloudAP read garbage and unload the plug-in a few milliseconds later.
`Context` is whatever the plug-in wants back: cloudAP passes it as the first argument of every slot.

The **name** matters more than it looks. It is how cloudAP finds the plug-in at logon time, and it
must be the same string as the `Name` value of the `Providers` key (see "Routing").

Bits of `Flags` that cloudAP tests: `0x01` skips the DPAPI key sync, `0x04` is needed to be chosen
by the surrogate for a smart card logon, `0x10` makes the plug-in the default one.

## What cloudAP gives the plug-in

`CLOUDAP_SECPKG_FUNCTION_TABLE` is 15 entries. `cloudAP!SpInitialize` fills it once: most entries are
copied from the `LSA_SECPKG_FUNCTION_TABLE` LSA gave cloudAP, so they have their typedef in
`ntsecpkg.h` already. The five others are cloudAP functions, typed from their public symbols.

| # | entry | type | from |
|---|-------|------|------|
| 0 | ImpersonateClient | `PLSA_IMPERSONATE_CLIENT` | LSA +0x58 |
| 1 | LsaProtectMemory | `PLSA_PROTECT_MEMORY` | LSA +0x160 |
| 2 | LsaUnprotectMemory | `PLSA_PROTECT_MEMORY` | LSA +0x168 |
| 3 | OpenTokenByLogonId | `PLSA_OPEN_TOKEN_BY_LOGON_ID` | LSA +0x170 |
| 4 | AllocateLsaHeap | `PLSA_ALLOCATE_LSA_HEAP` | LSA +0x28 |
| 5 | FreeLsaHeap | `PLSA_FREE_LSA_HEAP` | LSA +0x30 |
| 6 | AllocateUserInfo | `CLOUDAP_ALLOCATE_USER_INFO*` | cloudAP |
| 7 | FreeUserInfo | `CLOUDAP_FREE_USER_INFO*` | cloudAP |
| 8 | CrediRead | `CredReadFn*` | LSA +0x148 |
| 9 | CrediFreeCredentials | `CredFreeCredentialsFn*` | LSA +0x158 |
| 10 | CrediWrite | `CredWriteFn*` | LSA +0x198 |
| 11 | SignMessageWithNgc | `CLOUDAP_SIGN_MESSAGE_WITH_NGC*` | cloudAP |
| 12 | GetCallInfo | `PLSA_GET_CALL_INFO` | LSA +0xC0 |
| 13 | GenerateKeyBindingKeyPair | `CLOUDAP_GENERATE_KEY_BINDING_KEY_PAIR*` | cloudAP |
| 14 | VerifyKeyBindingKeyPair | `CLOUDAP_VERIFY_KEY_BINDING_KEY_PAIR*` | cloudAP |

`CredReadFn`, `CredWriteFn` and `CredFreeCredentialsFn` are in `ntsecpkg.h` but only when `wincred.h`
is included first; without it, those slots of `LSA_SECPKG_FUNCTION_TABLE` are named
`DummyFunction1..5`. Right after the table in cloudAP's memory comes `g_pLsaFunctionTable`, a
different variable: an early version of this plug-in read it as "entry 15" to reach `AllocateLsaHeap`.
It worked by accident; entry 4 is the real one.

## The plug-in table

`APPLUGIN_SECPKG_FUNCTION_TABLE` = `{ ULONG Version; NoNetwork[9]; NetworkOk[12]; }`: the Microsoft
plug-ins build it from two static tables, the functions that work without network and the others.
The names and prototypes come from the aad and MSA symbols (all in `CloudAp.h`):

| slot | function | | slot | function |
|------|----------|-|------|----------|
| 0 | Uninitialize | | 11 | **GetKeys** |
| 1 | ValidateUserInfo | | 12 | LookupSIDFromIdentityName |
| 2 | GetUnlockKey | | 13 | LookupIdentityFromSIDName |
| 3 | (unnamed, NULL in aad and MSA) | | 14 | UserProfileLoaded |
| 4 | GetDefaultCredentialComplexity | | 15 | ConnectIdentity |
| 5 | IsConnected | | 16 | DisconnectIdentity |
| 6 | AcceptPeerCertificate | | 17 | RenewCertificate |
| 7 | AssembleOpaqueData | | 18 | GetCertificateFromCred |
| 8 | DisassembleOpaqueData | | 19 | GenericCallPkg |
| 9 | **GetToken** | | 20 | PostLogonProcessing |
| 10 | RefreshToken | | | |

Only two are needed for an interactive logon. The others are stubs here that log the call and return
`STATUS_NOT_IMPLEMENTED`; cloudAP accepts that for the ones seen so far. Note that a NULL slot and a
failing stub are not the same thing: cloudAP skips some NULL slots (3 and 14 in `SyncDpapiKey`) but
takes a stub's error as a failure.

**GetToken** (slot 9) is the first function a logon reaches:

```c
NTSTATUS GetToken(PVOID Context, SECURITY_LOGON_TYPE LogonType,
    DECRYPTED_AUTH_DATA* Auth,       // { PWSTR UserLower; PWSTR User; SEC_WINNT_AUTH_PACKED_CREDENTIALS* Creds; }
    AP_BLOB* BlobIn, AP_BLOB* BlobOut,
    APPLUGIN_USER_INFO** UserInfo, SECPKG_SUPPLEMENTAL_CRED_ARRAY** Supplemental);
```

The plug-in checks the credential and returns a user info built with callback 6. cloudAP turns it
into the token with `MakeTokenInformationV2`, which reads only the user SID and the group list. So
the identity must be a SID LSA can resolve: here, a local account with the name of the logon user.
`BlobOut` (allocated on the LSA heap) is kept by cloudAP in its user cache and given back to
`GetKeys`.

**GetKeys** (slot 11) is called right after, by `cloudAP!GetDPAPIKeys`. It returns the credential key
LSA uses to protect the user's DPAPI master keys:

```c
NTSTATUS GetKeys(PVOID Context, AP_BLOB* Blob, GUID* KeyId, AP_BLOB* SavedKeyBlob, BOOL Flag,
    CREDENTIAL_KEY** Key, int* NeedNewKey, CREDENTIAL_KEY** Key2, AP_BLOB* KeyBlobOut);
// CREDENTIAL_KEY = { ULONG cbTotal; ULONG 0; ULONG cbHeader = 0x20; ULONG cbKey; GUID Id; BYTE Key[]; }
```

When cloudAP asks for `Key2`, it also needs a non-empty `KeyBlobOut`, else the logon fails with
`STATUS_INTERNAL_ERROR`.

## Routing: how a logon reaches the plug-in

There are three ways in, and only two work on a machine that is not joined to Entra ID.

**1. The logon buffer, sent to the CloudAP package.** A `SEC_WINNT_AUTH_IDENTITY_EX2` (documented,
version `0x201`) with:

- `User` = the user name,
- `Domain` = the plug-in name (`MYCP`),
- `PackedCredentials` = a `SEC_WINNT_AUTH_PACKED_CREDENTIALS` (credential type GUID + bytes; it must
  not be empty).

`cloudAP!LsaApLogonUserEx2` compares `Domain` with the name of every loaded plug-in and calls that
plug-in. This is what `credprov\CloudApCp` serializes and what `scripts\Test-Logon.ps1` sends with
`LsaLogonUser`.

**2. A normal password logon, `MYCP\user`.** The inbox password tile sends a
`KERB_INTERACTIVE_UNLOCK_LOGON` to Negotiate. When the domain is the name of an identity provider
registered with LSA, `lsasrv!LsapConvertLogonAuthInfo` rewrites it into the EX2 above, and Negotiate
hands it to CloudAP. This is how `AzureAD\user` works. That is why the plug-in name and the `Name` of
the `Providers` key must be the same: lsasrv looks up one, cloudAP the other. With both set to `MYCP`,
typing `MYCP\user` in the standard tile logs on through the plug-in, no credential provider needed.

**3. The surrogate (what Entra ID uses).** `cloudAP!LsaApPreLogonUserSurrogate` runs on every
interactive logon, but gives up at once unless the machine has a primary domain SID (joined), and
then only takes FIDO, NGC or delegation-token credentials. Not usable for a third-party provider on
a workgroup machine.

## DPAPI

Inside a session opened through the plug-in, DPAPI works. But if the same local account also logs on
with its password, the two kinds of sessions do not share master keys: MSV protects them with a key
derived from the password, the plug-in with the key from `GetKeys`. Each side then creates new master
keys and data protected in one kind of session cannot be read in the other. Entra ID accounts avoid
this because they only ever log on through CloudAP.

## Building

Visual Studio 2022 or later. The projects use the v145 toolset; retarget them or override it:

```
msbuild plugin\CloudApPlugin.vcxproj -p:Configuration=Release -p:Platform=x64
msbuild credprov\CloudApCp.vcxproj -p:Configuration=Release -p:Platform=x64
```

## Setting it up

In an elevated prompt, on a test VM:

1. Copy `plugin\bin\CloudApPlugin.dll` to `C:\Windows\System32`.
2. `scripts\Provider.ps1 -Step Register`, then reboot (or run `scripts\Reinit-Plugins.ps1` as SYSTEM).
3. `scripts\Provider.ps1 -Step Show`: the log tells whether cloudAP loaded the plug-in. On a stock
   Windows it does not, see the warning at the top.
4. As SYSTEM: `scripts\Test-Logon.ps1 -User <local account>`. The output shows the token, with
   authentication type `CloudAP`. A wrong secret gives `0xC000006D`.
5. Optional: `scripts\CredentialProvider.ps1 -Step Register` adds a tile "CloudAP lab IdP (MYCP)" to
   the logon and lock screens.

In my lab (Windows 11 26100, workgroup, offline) the user logs on and unlocks through LogonUI, with
the tile or with `MYCP\user` in the standard password tile. Event 4624 shows a type 2 logon whose
session belongs to the CloudAP package.

## What is left

- A real credential: the secret is a constant. The plan is a smart card certificate (CN = local
  account) with the PIN checked by the card.
- A DPAPI key derived from a secret of the user, not from the SID.
- The slots that are still stubs: `GetUnlockKey` (unlock with cached keys), `RefreshToken`, the
  SID/name lookups, `GenericCallPkg`.
- And above all, the signature: without a Microsoft-signed plug-in, none of this runs on a normal
  machine.

## License

MIT, see [LICENSE](LICENSE).
