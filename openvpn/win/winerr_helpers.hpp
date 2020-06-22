/**
 * Ported from the UH VPN Windows codebase.
 */

#pragma once

#include <codecvt>
#include <string>

#include <windows.h>

namespace openvpn {
  namespace Win {
    // Takes an error code from GetLastError() and returns a std::string containing
    // the written error message from the system.
    inline std::string win32_error_to_string(DWORD error_code)
      {
	LPVOID message_buffer;
	FormatMessageW(
	    FORMAT_MESSAGE_ALLOCATE_BUFFER |
	    FORMAT_MESSAGE_FROM_SYSTEM |
	    FORMAT_MESSAGE_IGNORE_INSERTS,
	    NULL,
	    error_code,
	    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
	    (LPWSTR) &message_buffer,
	    0,
	    NULL
	);
	std::wstring result((LPWSTR) message_buffer);
	LocalFree(message_buffer);
	std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
	// Remove trailing \r\n from FormatMessage and convert to UTF-8 string.
	return conv.to_bytes(result.substr(0, result.size()-2))
	    + "[" + std::to_string(error_code) + "]";
      }

  }
}
