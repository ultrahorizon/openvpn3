//    OpenVPN -- An application to securely tunnel IP networks
//               over a single TCP/UDP port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

#pragma once

#include <windows.h>

namespace openvpn::Win {

/**
 * @brief Whether a process with this id is running
 *
 * Used to tell state a running process owns from state a process that ended without its
 * teardown left behind. A process that exists but may not be opened counts as running.
 * A reused id makes a dead owner look alive: state is then kept, never wrongly removed.
 */
inline bool process_running(const DWORD pid)
{
    if (!pid)
        return false;
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h)
        return ::GetLastError() == ERROR_ACCESS_DENIED;
    DWORD code = 0;
    const bool running = ::GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
    ::CloseHandle(h);
    return running;
}

} // namespace openvpn::Win
