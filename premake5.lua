workspace "MGSResolutionPatch"
   configurations { "Debug", "Release" }
   architecture "x64"
   location "build"
   buildoptions {"-std:c++latest"}
   
   defines { "X64" }
     
project "MGSResolutionPatch"
   kind "SharedLib"
   language "C++"
   targetdir "bin/x64/%{cfg.buildcfg}"
   targetname "MGSResolutionPatch"
   targetextension ".asi"
   
   includedirs { "source" }
   includedirs { "external" }
   
   files { "source/dllmain.h", "source/dllmain.cpp", "external/Hooking.Patterns/Hooking.Patterns.cpp", "external/Hooking.Patterns/Hooking.Patterns.h" }
   
   characterset ("UNICODE")
   
   filter "configurations:Debug"
      defines { "DEBUG" }
      symbols "On"

   filter "configurations:Release"
      defines { "NDEBUG" }
      optimize "On"
      staticruntime "On"
      