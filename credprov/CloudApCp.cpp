// CloudApCp - minimal credential provider for the CloudAP plug-in (CloudApPlugin, provider MYCP).
//
// One tile: account name + PIN + submit. GetSerialization returns the SEC_WINNT_AUTH_IDENTITY_EX2 that
// cloudAP!_LsaApLogonUserEx2 routes by Domain to the plug-in (Ex2.h), for the "CloudAP" package: no
// surrogate, no cloud join. The credential is a SEC_WINNT_AUTH_DATA_TYPE_PASSWORD packed credential
// holding the PIN; put your own credential type and bytes there.
// Scenarios: CPUS_LOGON and CPUS_UNLOCK_WORKSTATION. Register with scripts\CredentialProvider.ps1.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <initguid.h>
#include <credentialprovider.h>
#include <ntsecapi.h>
#include <cguid.h>
#include <shlguid.h>                                     // CPFG_* field GUIDs
#include <shlwapi.h>
#include <strsafe.h>
#include <new>
#include "Ex2.h"

// {A52F0DC0-248F-469F-B8B7-3284B490519B}
DEFINE_GUID(CLSID_CloudApCp, 0xa52f0dc0, 0x248f, 0x469f, 0xb8, 0xb7, 0x32, 0x84, 0xb4, 0x90, 0x51, 0x9b);

static LONG g_refs;
static HINSTANCE g_instance;

enum FieldId { FID_LABEL, FID_USER, FID_PIN, FID_SUBMIT, FID_COUNT };

static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR g_fields[FID_COUNT] = {
    { FID_LABEL,  CPFT_LARGE_TEXT,    const_cast<PWSTR>(L"Label"),   CPFG_CREDENTIAL_PROVIDER_LABEL },
    { FID_USER,   CPFT_EDIT_TEXT,     const_cast<PWSTR>(L"Account"), CPFG_LOGON_USERNAME },
    { FID_PIN,    CPFT_PASSWORD_TEXT, const_cast<PWSTR>(L"PIN"),     CPFG_LOGON_PASSWORD },
    { FID_SUBMIT, CPFT_SUBMIT_BUTTON, const_cast<PWSTR>(L"Submit"),  GUID_NULL },
};

static const CREDENTIAL_PROVIDER_FIELD_STATE g_states[FID_COUNT] = {
    CPFS_DISPLAY_IN_BOTH, CPFS_DISPLAY_IN_SELECTED_TILE, CPFS_DISPLAY_IN_SELECTED_TILE, CPFS_DISPLAY_IN_SELECTED_TILE,
};

static HRESULT CopyField(PCWSTR source, PWSTR* out)
{
    return SHStrDupW(source ? source : L"", out);
}

// The CloudAP package id, as LogonUI hands it to LsaLogonUser.
static HRESULT LookupCloudAp(ULONG* package)
{
    HANDLE lsa;
    NTSTATUS status = LsaConnectUntrusted(&lsa);
    if (status != 0) return HRESULT_FROM_NT(status);
    char name[] = "CloudAP";
    LSA_STRING s = { (USHORT)(sizeof(name) - 1), (USHORT)sizeof(name), name };
    status = LsaLookupAuthenticationPackage(lsa, &s, package);
    LsaDeregisterLogonProcess(lsa);
    return HRESULT_FROM_NT(status);
}

class Credential : public ICredentialProviderCredential
{
    LONG m_refs = 1;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO m_scenario;
    WCHAR m_user[256] = L"";
    WCHAR m_pin[64] = L"";
public:
    explicit Credential(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario) : m_scenario(scenario) { InterlockedIncrement(&g_refs); }
    ~Credential() { SecureZeroMemory(m_pin, sizeof(m_pin)); InterlockedDecrement(&g_refs); }

    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv)
    {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredential) { *ppv = this; AddRef(); return S_OK; }
        *ppv = NULL;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP_(ULONG) AddRef() { return InterlockedIncrement(&m_refs); }
    IFACEMETHODIMP_(ULONG) Release() { LONG r = InterlockedDecrement(&m_refs); if (!r) delete this; return r; }

    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents*) { return S_OK; }
    IFACEMETHODIMP UnAdvise() { return S_OK; }
    IFACEMETHODIMP SetSelected(BOOL* autoLogon) { *autoLogon = FALSE; return S_OK; }
    IFACEMETHODIMP SetDeselected() { SecureZeroMemory(m_pin, sizeof(m_pin)); return S_OK; }

    IFACEMETHODIMP GetFieldState(DWORD id, CREDENTIAL_PROVIDER_FIELD_STATE* state, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactive)
    {
        if (id >= FID_COUNT || !state || !interactive) return E_INVALIDARG;
        *state = g_states[id];
        *interactive = id == FID_USER ? CPFIS_FOCUSED : CPFIS_NONE;
        return S_OK;
    }
    IFACEMETHODIMP GetStringValue(DWORD id, PWSTR* value)
    {
        switch (id)
        {
        case FID_LABEL: return CopyField(L"CloudAP lab IdP (" CLOUDAP_LAB_PROVIDER L")", value);
        case FID_USER: return CopyField(m_user, value);
        case FID_PIN: return CopyField(L"", value);
        default: return E_INVALIDARG;
        }
    }
    IFACEMETHODIMP GetBitmapValue(DWORD, HBITMAP*) { return E_NOTIMPL; }
    IFACEMETHODIMP GetCheckboxValue(DWORD, BOOL*, PWSTR*) { return E_NOTIMPL; }
    IFACEMETHODIMP GetSubmitButtonValue(DWORD id, DWORD* adjacent)
    {
        if (id != FID_SUBMIT || !adjacent) return E_INVALIDARG;
        *adjacent = FID_PIN;
        return S_OK;
    }
    IFACEMETHODIMP GetComboBoxValueCount(DWORD, DWORD*, DWORD*) { return E_NOTIMPL; }
    IFACEMETHODIMP GetComboBoxValueAt(DWORD, DWORD, PWSTR*) { return E_NOTIMPL; }
    IFACEMETHODIMP SetStringValue(DWORD id, PCWSTR value)
    {
        switch (id)
        {
        case FID_USER: return StringCchCopyW(m_user, ARRAYSIZE(m_user), value ? value : L"");
        case FID_PIN: return StringCchCopyW(m_pin, ARRAYSIZE(m_pin), value ? value : L"");
        default: return E_INVALIDARG;
        }
    }
    IFACEMETHODIMP SetCheckboxValue(DWORD, BOOL) { return E_NOTIMPL; }
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD, DWORD) { return E_NOTIMPL; }
    IFACEMETHODIMP CommandLinkClicked(DWORD) { return E_NOTIMPL; }

    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization, PWSTR* statusText, CREDENTIAL_PROVIDER_STATUS_ICON* icon)
    {
        *response = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        *statusText = NULL;
        *icon = CPSI_NONE;
        ZeroMemory(serialization, sizeof(*serialization));
        if (!m_user[0]) return SHStrDupW(L"Enter the account name.", statusText);
        ULONG package;
        HRESULT hr = LookupCloudAp(&package);
        if (FAILED(hr)) return hr;
        ULONG cb;
        PBYTE b = BuildEx2(m_user, CLOUDAP_LAB_PROVIDER, SEC_WINNT_AUTH_DATA_TYPE_PASSWORD, m_pin,
            (ULONG)(wcslen(m_pin) * sizeof(WCHAR)), &cb, [](ULONG n) { return CoTaskMemAlloc(n); });
        if (!b) return E_OUTOFMEMORY;
        serialization->ulAuthenticationPackage = package;
        serialization->clsidCredentialProvider = CLSID_CloudApCp;
        serialization->cbSerialization = cb;
        serialization->rgbSerialization = b;
        *response = CPGSR_RETURN_CREDENTIAL_FINISHED;
        return S_OK;
    }
    IFACEMETHODIMP ReportResult(NTSTATUS status, NTSTATUS subStatus, PWSTR* statusText, CREDENTIAL_PROVIDER_STATUS_ICON* icon)
    {
        *statusText = NULL;
        *icon = CPSI_NONE;
        if (status == 0) return S_OK;
        WCHAR text[128];
        StringCchPrintfW(text, ARRAYSIZE(text), L"CloudAP logon failed: 0x%08lX (sub 0x%08lX)", status, subStatus);
        *icon = CPSI_ERROR;
        return SHStrDupW(text, statusText);
    }
};

class Provider : public ICredentialProvider
{
    LONG m_refs = 1;
    Credential* m_credential = NULL;
public:
    Provider() { InterlockedIncrement(&g_refs); }
    ~Provider() { if (m_credential) m_credential->Release(); InterlockedDecrement(&g_refs); }

    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv)
    {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_ICredentialProvider) { *ppv = this; AddRef(); return S_OK; }
        *ppv = NULL;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP_(ULONG) AddRef() { return InterlockedIncrement(&m_refs); }
    IFACEMETHODIMP_(ULONG) Release() { LONG r = InterlockedDecrement(&m_refs); if (!r) delete this; return r; }

    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, DWORD)
    {
        if (scenario != CPUS_LOGON && scenario != CPUS_UNLOCK_WORKSTATION) return E_NOTIMPL;
        if (m_credential) m_credential->Release();
        m_credential = new (std::nothrow) Credential(scenario);
        return m_credential ? S_OK : E_OUTOFMEMORY;
    }
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) { return E_NOTIMPL; }
    IFACEMETHODIMP Advise(ICredentialProviderEvents*, UINT_PTR) { return S_OK; }
    IFACEMETHODIMP UnAdvise() { return S_OK; }
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* count) { *count = FID_COUNT; return S_OK; }
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD index, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** out)
    {
        if (index >= FID_COUNT || !out) return E_INVALIDARG;
        auto* d = (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(**out));
        if (!d) return E_OUTOFMEMORY;
        *d = g_fields[index];
        if (FAILED(SHStrDupW(g_fields[index].pszLabel, &d->pszLabel))) { CoTaskMemFree(d); return E_OUTOFMEMORY; }
        *out = d;
        return S_OK;
    }
    IFACEMETHODIMP GetCredentialCount(DWORD* count, DWORD* defaultIndex, BOOL* autoLogon)
    {
        *count = m_credential ? 1 : 0;
        *autoLogon = FALSE;
        *defaultIndex = CREDENTIAL_PROVIDER_NO_DEFAULT;
        return S_OK;
    }
    IFACEMETHODIMP GetCredentialAt(DWORD index, ICredentialProviderCredential** out)
    {
        if (index != 0 || !m_credential || !out) return E_INVALIDARG;
        return m_credential->QueryInterface(IID_ICredentialProviderCredential, (void**)out);
    }
};

class Factory : public IClassFactory
{
public:
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv)
    {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IClassFactory) { *ppv = this; return S_OK; }
        *ppv = NULL;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP_(ULONG) AddRef() { return 2; }
    IFACEMETHODIMP_(ULONG) Release() { return 1; }
    IFACEMETHODIMP CreateInstance(IUnknown* outer, REFIID riid, void** ppv)
    {
        if (outer) return CLASS_E_NOAGGREGATION;
        Provider* p = new (std::nothrow) Provider();
        if (!p) return E_OUTOFMEMORY;
        HRESULT hr = p->QueryInterface(riid, ppv);
        p->Release();
        return hr;
    }
    IFACEMETHODIMP LockServer(BOOL lock) { lock ? InterlockedIncrement(&g_refs) : InterlockedDecrement(&g_refs); return S_OK; }
};

static Factory g_factory;

STDAPI DllGetClassObject(REFCLSID clsid, REFIID riid, void** ppv)
{
    if (clsid != CLSID_CloudApCp) return CLASS_E_CLASSNOTAVAILABLE;
    return g_factory.QueryInterface(riid, ppv);
}

STDAPI DllCanUnloadNow()
{
    return g_refs ? S_FALSE : S_OK;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, PVOID)
{
    if (reason == DLL_PROCESS_ATTACH) { g_instance = instance; DisableThreadLibraryCalls(instance); }
    return TRUE;
}
