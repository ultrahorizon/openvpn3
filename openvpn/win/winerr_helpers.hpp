/**
 * Ported from the UH VPN Windows codebase.
 */

#pragma once

#include <string>

#include <windows.h>

#include <openvpn/common/wstring.hpp>

namespace openvpn::Win {

// Takes an error code from GetLastError() and returns a std::string containing
// the written error message from the system.
inline std::string win32_error_to_string(DWORD error_code)
{
    LPWSTR message_buffer = nullptr;
    const DWORD len = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error_code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&message_buffer,
        0,
        nullptr);
    std::wstring result;
    if (len && message_buffer)
        result.assign(message_buffer, len);
    if (message_buffer)
        ::LocalFree(message_buffer);
    // Remove trailing \r\n from FormatMessage and convert to UTF-8 string.
    while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n'))
        result.pop_back();
    return wstring::to_utf8(result) + "[" + std::to_string(error_code) + "]";
}

} // namespace openvpn::Win
