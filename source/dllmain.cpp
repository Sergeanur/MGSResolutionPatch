#include <windows.h>
#include <Hooking.Patterns\Hooking.Patterns.h>
#include <thread>

struct ResEntry
{
    int field_0 = 1; // widescreen?
    float fAspectRatio = 0;
    unsigned int WindowSizeX = 0, ResolutionX = 0;
    unsigned int WindowSizeY = 0, ResolutionY = 0;
};

std::thread* tempThread = nullptr;

void SetResolutionHook(hook::pattern& pattern, const ResEntry& newResolution)
{
    DWORD protect[2];
    if (VirtualProtect(pattern.get_first(0), 0x100, PAGE_EXECUTE_READWRITE, &protect[0]))
    {
        *(int*)pattern.get_first(3) = newResolution.field_0;
        *(float*)pattern.get_first(10) = newResolution.fAspectRatio;
        *(unsigned int*)pattern.get_first(17) = newResolution.WindowSizeX;
        *(unsigned int*)pattern.get_first(24) = newResolution.WindowSizeY;
        *(unsigned int*)pattern.get_first(31) = newResolution.ResolutionX;
        *(unsigned int*)pattern.get_first(38) = newResolution.ResolutionY;

        *(unsigned int*)pattern.get_first(252) = 1;

        VirtualProtect(pattern.get_first(0), 0x100, protect[0], &protect[1]);
    }

    // UI fix (MGS 2)
    pattern = hook::pattern("66 0F 6E 45 F8");
    if (!pattern.empty())
    {
        // X scale constant used in some other code too, so move it to the other place for safety reasons
        float* pXScale = (float*)((char*)pattern.get_first(9+4) + *(int*)pattern.get_first(9));
        float XScale = *pXScale * ((float)newResolution.ResolutionX / 1280.0f);
        pXScale -= 35; // some align space after 'vector too long'

        if (VirtualProtect(pXScale, 4, PAGE_READWRITE, &protect[0]))
        {
            *pXScale = XScale;
            VirtualProtect(pXScale, 4, protect[0], &protect[1]);
        }

        if (VirtualProtect(pattern.get_first(9), 4, PAGE_READWRITE, &protect[0]))
        {
            *(int*)pattern.get_first(9) -= 0x8C;
            VirtualProtect(pattern.get_first(9), 4, protect[0], &protect[1]);
        }

        if (VirtualProtect(pattern.get_first(52), 4, PAGE_READWRITE, &protect[0]))
        {
            *(int*)pattern.get_first(52) -= 0x8C;
            VirtualProtect(pattern.get_first(52), 4, protect[0], &protect[1]);
        }

        // Y scale only used once, so modify in-place
        float* pYScale = (float*)((char*)pattern.get_first(0x64) + *(int*)pattern.get_first(0x60));
        float YScale = *pYScale * ((float)newResolution.ResolutionY / 720.0f);
        if (VirtualProtect(pYScale, 4, PAGE_READWRITE, &protect[0]))
        {
            *pYScale = YScale;
            VirtualProtect(pYScale, 4, protect[0], &protect[1]);
        }
    }
    
}

ResEntry newResolution;

void threadWaitingLoop(hook::pattern pattern)
{
    while (*pattern.get_first<int>(0) != 0x018745C7 && *pattern.get_first<int>(252) != 6)
    {
        std::this_thread::yield();
    }

    SetResolutionHook(pattern, newResolution);
}

std::wstring GetModulePath(HMODULE hModule)
{
    std::wstring path;
    path.resize(MAX_PATH);

    while (true)
    {
        auto ret = GetModuleFileNameW(hModule, path.data(), static_cast<DWORD>(path.size()));
        if (ret == 0)
            return L"";
        if (ret == path.size())
            path.resize(path.size() * 2);
        else
            return path;
    }

    return path;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        std::wstring ModulePath = GetModulePath(hModule);
        ModulePath.resize(ModulePath.find_last_of(L'.'));
        ModulePath += L".ini";
        if (!ModulePath.empty())
        {
            INT Value;

            Value = GetPrivateProfileInt(L"MGSResolutionPatch", L"WindowSizeX", 0, ModulePath.c_str());
            if (Value > 0) newResolution.ResolutionX = Value;

            Value = GetPrivateProfileInt(L"MGSResolutionPatch", L"WindowSizeY", 0, ModulePath.c_str());
            if (Value > 0) newResolution.ResolutionY = Value;

            Value = GetPrivateProfileInt(L"MGSResolutionPatch", L"ResolutionX", 0, ModulePath.c_str());
            if (Value > 0) newResolution.WindowSizeX = Value;

            Value = GetPrivateProfileInt(L"MGSResolutionPatch", L"ResolutionY", 0, ModulePath.c_str());
            if (Value > 0) newResolution.WindowSizeY = Value;

            Value = GetPrivateProfileInt(L"MGSResolutionPatch", L"SquishVertically", 1, ModulePath.c_str());
            newResolution.field_0 = !!Value;

            if (newResolution.ResolutionX == 0 || newResolution.ResolutionY == 0 || newResolution.WindowSizeX == 0 || newResolution.WindowSizeY == 0) // no valid resolution
                return TRUE;

            newResolution.fAspectRatio = (float)newResolution.WindowSizeX / (float)newResolution.WindowSizeY;

            auto pattern = hook::pattern("C7 45 87 01 00 00 00");

            if (!pattern.empty())
            {
                SetResolutionHook(pattern, newResolution);
            }
            else
            {
                // look for encrypted patterns
                pattern = hook::pattern("4C DA 57 A8 25 E2"); // MGS3
                if (!pattern.empty())
                    tempThread = new std::thread(threadWaitingLoop, pattern);
                else
                {
                    pattern = hook::pattern("90 89 26 34 BB 0E 63 7C"); // MGS2
                    if (!pattern.empty())
                        tempThread = new std::thread(threadWaitingLoop, pattern);
                }
            }
        }

    }
    if (reason == DLL_PROCESS_DETACH)
    {
        delete tempThread;
    }
    return TRUE;
}