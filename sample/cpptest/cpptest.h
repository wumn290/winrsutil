#pragma once
#include <windows.h>

extern "C" {
    __declspec(dllimport) unsigned int __cdecl SaveExeIcon(const char* filename, const char* savepath);
    __declspec(dllimport) unsigned int __cdecl SetRegistryValue(HKEY key, const char* sub_key, const char* value_name, DWORD regtype, char* data, DWORD len);
    __declspec(dllimport) unsigned int __cdecl QueryRegistryValue(HKEY key, const char* sub_key, const char* value_name, DWORD* regtype, char* data, DWORD* len);
    __declspec(dllimport) unsigned int __cdecl DeleteRegistryValue(HKEY key, const char* sub_key, const char* value_name);
    __declspec(dllimport) unsigned int __cdecl GetFileSignerName(const char* filepath,  char* name,  DWORD* len);
    __declspec(dllimport) unsigned int __cdecl GetFileVersionValue(const char* valuename, const char* modulename, char* data, DWORD* len);
    __declspec(dllimport) unsigned int __cdecl ExecWmi(const char* classname, const char* condition, const char* namespac, const char* key, char* data, DWORD* len);
}
