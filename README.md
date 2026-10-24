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

```c
NTSTATUS CloudAPPluginInitialize(
    ULONG       Version,          // 1
    const GUID* ProviderGuid,
    PVOID*      CloudApTable,     // callbacks given by cloudAP, see below
    PULONG      Flags,            // out
    PWSTR       Name,             // out, WCHAR[21]
    PSID        Sid,              // out, buffer in cloudAP's record, must pass RtlValidSid
    PVOID*      Sid2,             // out, optional
    PVOID*      Reserved,         // out, NULL is fine
    PVOID       PluginTable);     // out, 0xB0 bytes to FILL, not a pointer to store
```

All the out-parameters point into the 0x188-byte record cloudAP keeps for the plug-in. The last one
is the easy mistake: cloudAP passes a buffer and the plug-in copies its table into it. Storing a
pointer there makes cloudAP read garbage and unload the plug-in a few milliseconds later.

The **name** matters more than it looks. It is how cloudAP finds the plug-in at logon time, and it
must be the same string as the `Name` value of the `Providers` key (see "Routing").

Useful callbacks in `CloudApTable`:

| index | function                     | use |
|-------|------------------------------|-----|
| 6     | `cloudAP!AllocateUserInfo`   | builds the user info `GetToken` returns |
| 7     | `cloudAP!FreeUserInfo`       | |
| 8-10  | `lsasrv!CrediRead/Free/Write`| credential manager |
| 15    | `LSA_SECPKG_FUNCTION_TABLE`  | `AllocateLsaHeap` for everything cloudAP frees |

## The plug-in table

`{ ULONG Version; PVOID Functions[21]; }`. The names are those of the Microsoft plug-ins' symbols:

| slot | function | | slot | function |
|------|----------|-|------|----------|
| 0 | Uninitialize | | 11 | **GetKeys** |
| 1 | ValidateUserInfo | | 12 | LookupSIDFromIdentityName |
| 2 | GetUnlockKey | | 13 | LookupIdentityFromSIDName |
| 3 | (MSA only) | | 14 | UserProfileLoaded |
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
