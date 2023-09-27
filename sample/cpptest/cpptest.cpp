// cpptest.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "cpptest.h"

int main()
{
    unsigned int ret = SaveExeIcon("C:\\Windows\\System32\\cmd.exe", "C:\\Users\\86187\\AppData\\Local\\Temp\\winrsutil_cpp_test184341.ico");
    std::cout << "SaveExeIcon, ret = " << ret <<"\n";
    const char* data = "收到房间号sf123cpp南方的鈤yu😂1";
    DWORD len = strlen(data);
    ret = SetRegistryValue(HKEY_CURRENT_USER, "SOFTWARE\\test_cpp0923", "test_sz_value", REG_SZ, (char*)data, len);
    std::cout << "SetRegistryValue, test_sz_value, ret = " << ret << "\n";
    DWORD dwValue = 7225399;
    len = sizeof(DWORD);
    ret = SetRegistryValue(HKEY_CURRENT_USER, "SOFTWARE\\test_cpp0923", "test_dword_value", REG_SZ, (char*) &dwValue, len);
    std::cout << "SetRegistryValue, test_dword_value, ret = " << ret << "\n";
    DWORD regtype;
    char szRegData[MAX_PATH] = { 0 };
    len = MAX_PATH;
    ret = QueryRegistryValue(HKEY_CURRENT_USER, "SOFTWARE\\test_cpp0923", "test_sz_value", &regtype, (char*)szRegData, &len);
    std::cout << "QueryRegistryValue, test_sz_value, ret = " << ret << ", szRegData=" << szRegData << "\n";
    len = MAX_PATH;
    ret = QueryRegistryValue(HKEY_CURRENT_USER, "SOFTWARE\\test_cpp0923", "test_dword_value", &regtype, (char*)szRegData, &len);
    std::cout << "QueryRegistryValue, test_dword_value, ret = " << ret << ", data=" << *(DWORD*)szRegData << "\n";
    ret = DeleteRegistryValue(HKEY_CURRENT_USER, "SOFTWARE\\test_cpp0923", "test_sz_value");
    std::cout << "DeleteRegistryValue, test_sz_value, ret = " << ret << "\n";
    ret = DeleteRegistryValue(HKEY_CURRENT_USER, "SOFTWARE\\test_cpp0923", "test_dword_value");
    std::cout << "DeleteRegistryValue, test_dword_value, ret = " << ret << "\n";
    ret = DeleteRegistryValue(HKEY_CURRENT_USER, "SOFTWARE\\test_cpp0923", NULL);
    std::cout << "DeleteRegistryValue, null, ret = " << ret << "\n";
    char szSignName[MAX_PATH] = { 0 };
    len = MAX_PATH;
    ret = GetFileSignerName("C:\\Windows\\explorer.exe", szSignName, &len);
    std::cout << "GetFileSignerName, ret = " << ret << ", szSignName = " << szSignName << "\n";
    char szVersionValue[MAX_PATH] = { 0 };
    len = MAX_PATH;
    ret = GetFileVersionValue("FileDescription", "C:\\Windows\\System32\\cmd.exe", szVersionValue, &len);
    std::cout << "GetFileVersionValue, ret = " << ret << ", szVersionValue = " << szSignName << "\n";
    char szWmiValue[MAX_PATH] = { 0 };
    len = MAX_PATH;
    ret = ExecWmi("Win32_Processor", NULL, "root\\cimv2", "AddressWidth", szWmiValue, &len);
    std::cout << "ExecWmi, ret = " << ret << ", AddressWidth = " << szWmiValue << "\n";
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
