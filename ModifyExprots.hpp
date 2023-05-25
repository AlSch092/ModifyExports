#pragma once

#include <string>
#include <string_view>

namespace modify_exports {
    bool ModifyDLLExportName(std::string_view dllName, std::string_view functionName, std::string_view newName);
}