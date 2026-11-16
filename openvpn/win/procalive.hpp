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

#include <cstdint>

#include <openvpn/win/ownermark.hpp>

namespace openvpn::Win {

/**
 * @brief Whether a process with this id runs, and when it started
 *
 * The start time is the process creation time as a FILETIME (100 ns since 1601, UTC), absent if
 * it cannot be read. A process that exists but may not be opened counts as running with no start
 * time, so an owner check keeps its state (OwnerMark::judge).
 */
inline OwnerMark::Probe probe_process(const DWORD pid)
{
    OwnerMark::Probe p;
    if (!pid)
        return p;
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h)
    {
        p.running = ::GetLastError() == ERROR_ACCESS_DENIED;
        return p;
    }
    DWORD code = 0;
    p.running = ::GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
    FILETIME created, exited, kernel, user;
    if (p.running && ::GetProcessTimes(h, &created, &exited, &kernel, &user))
        p.start = (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    ::CloseHandle(h);
    return p;
}

// The owner mark of a process (normally this one): its id and start time.
inline OwnerMark::Owner process_owner(const DWORD pid)
{
    OwnerMark::Owner o;
    o.pid = pid;
    const OwnerMark::Probe p = probe_process(pid);
    if (p.running)
        o.start = p.start;
    return o;
}

// OwnerMark::judge with this process as self and the live process table as the probe.
inline OwnerMark::Verdict judge_owner(const std::optional<OwnerMark::Owner> &o)
{
    return OwnerMark::judge(o, process_owner(::GetCurrentProcessId()), [](std::uint32_t pid)
                            { return probe_process(pid); });
}

} // namespace openvpn::Win
