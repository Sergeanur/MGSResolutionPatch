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


std::wstring GetModuleFileNameW(HMODULE hModule)
{
    static constexpr auto INITIAL_BUFFER_SIZE = MAX_PATH;
    static constexpr auto MAX_ITERATIONS = 7;
    std::wstring ret;
    auto bufferSize = INITIAL_BUFFER_SIZE;
    for (size_t iterations = 0; iterations < MAX_ITERATIONS; ++iterations)
    {
        ret.resize(bufferSize);
        auto charsReturned = GetModuleFileNameW(hModule, &ret[0], bufferSize);
        if (charsReturned < ret.length())
        {
            ret.resize(charsReturned);
            return ret;
        }
        else
        {
            bufferSize *= 2;
        }
    }
    return L"";
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