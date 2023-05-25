
#include <catch2/catch_test_macros.hpp>
#include "../ModifyExprots.hpp"

#include <Windows.h>
#include <iostream>
#include <libloaderapi.h>

TEST_CASE("ModifyExports")
{
    auto user32 = GetModuleHandleW(L"user32");
    if (!user32) {
        LoadLibraryA("user32.dll");
        user32 = GetModuleHandleW(L"user32");
    }
    REQUIRE(user32);

	auto MsgBoxW = (UINT64)GetProcAddress(user32, "MessageBoxW");
    REQUIRE(MsgBoxW);

    std::cout << "MessageBoxW: " << std::hex << MsgBoxW << std::endl;

	modify_exports::ModifyDLLExportName("user32.dll", "MessageBoxW", "MessageBoxA"); //now we have two MessageBoxA symbols

	auto program = GetModuleHandleW(L"user32");
    REQUIRE(program);

	auto addr_W = (UINT64)GetProcAddress(program, "MessageBoxW"); //we call GetProcAddress again, which now returns 0
	auto addr_A = (UINT64)GetProcAddress(program, "MessageBoxA");

	REQUIRE(addr_W == 0);
    REQUIRE(addr_A != 0);
}