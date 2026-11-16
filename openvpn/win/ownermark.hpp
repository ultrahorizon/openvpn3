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

// Owner marks: who wrote a piece of shared system state (an NRPT rule, our domains in the DNS
// search list), so that a later cleanup removes only what a process that has ended left behind.
// An owner is a process id plus the process's start time; the id alone can be reused by an
// unrelated process. Plain C++ (no Windows headers), so that the parsing and the decision can be
// unit tested anywhere; the process probe is passed in.

#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace openvpn::OwnerMark {

struct Owner
{
    std::uint32_t pid = 0;
    std::optional<std::uint64_t> start; // process creation time (FILETIME); absent in old marks
};

// What the system says about a process id now.
struct Probe
{
    bool running = false;
    std::optional<std::uint64_t> start; // absent if it could not be read
};

enum class Verdict
{
    Own,        // this process
    Live,       // a running process that is (or may be) the owner: keep
    Gone,       // the owner has ended (or its id now belongs to another process): stale
    Unreadable, // not a mark we can read: keep, never touch
};

namespace detail {
inline std::optional<std::uint64_t> number(const std::wstring &s)
{
    if (s.empty() || s.size() > 20)
        return std::nullopt;
    std::uint64_t v = 0;
    for (const wchar_t c : s)
    {
        if (c < L'0' || c > L'9')
            return std::nullopt;
        const std::uint64_t d = static_cast<std::uint64_t>(c - L'0');
        if (v > (UINT64_MAX - d) / 10)
            return std::nullopt;
        v = v * 10 + d;
    }
    return v;
}
} // namespace detail

// "<pid>" or "<pid>:<start>", nothing else.
inline std::optional<Owner> parse_owner(const std::wstring &s)
{
    const auto colon = s.find(L':');
    const auto pid = detail::number(s.substr(0, colon));
    if (!pid || *pid == 0 || *pid > UINT32_MAX)
        return std::nullopt;
    Owner o;
    o.pid = static_cast<std::uint32_t>(*pid);
    if (colon != std::wstring::npos)
    {
        const auto start = detail::number(s.substr(colon + 1));
        if (!start)
            return std::nullopt;
        o.start = *start;
    }
    return o;
}

inline std::wstring format_owner(const Owner &o)
{
    std::wstring s = std::to_wstring(o.pid);
    if (o.start)
        s += L":" + std::to_wstring(*o.start);
    return s;
}

/**
 * @brief Is the owner still there?
 *
 * Gone only when it can be shown: the process is not running, or a process with that id runs
 * but started at another time than the mark says (the id was reused), or the mark names this
 * process's id with another start time (an earlier process had our id). A running process whose
 * start time cannot be read, or an old mark without a start time whose id is running, counts as
 * Live: when in doubt, keep.
 */
inline Verdict judge(const std::optional<Owner> &o,
                     const Owner &self,
                     const std::function<Probe(std::uint32_t)> &probe)
{
    if (!o || o->pid == 0)
        return Verdict::Unreadable;
    if (o->pid == self.pid)
    {
        if (o->start && self.start && *o->start != *self.start)
            return Verdict::Gone;
        return Verdict::Own;
    }
    const Probe p = probe(o->pid);
    if (!p.running)
        return Verdict::Gone;
    if (o->start && p.start && *o->start != *p.start)
        return Verdict::Gone;
    return Verdict::Live;
}

// ---- the DNS search list owner value: "<owner>|<S>|<domains>"
// S is 1 if the owner's session also took the snapshot of the list (InitialSearchList /
// OriginalSearchList), else 0. Marks from patch 0010 are "<pid>|<domains>" (no start, no S).

struct SearchListMark
{
    Owner owner;
    bool snapshot_ours = false;
    std::wstring domains;
};

inline std::optional<SearchListMark> parse_search_list_mark(const std::wstring &v)
{
    const auto bar1 = v.find(L'|');
    if (bar1 == std::wstring::npos)
        return std::nullopt;
    SearchListMark m;
    const auto o = parse_owner(v.substr(0, bar1));
    if (!o)
        return std::nullopt;
    m.owner = *o;
    const std::wstring rest = v.substr(bar1 + 1);
    const auto bar2 = rest.find(L'|');
    if (o->start && bar2 != std::wstring::npos && (rest.substr(0, bar2) == L"0" || rest.substr(0, bar2) == L"1"))
    {
        m.snapshot_ours = rest[0] == L'1';
        m.domains = rest.substr(bar2 + 1);
    }
    else if (!o->start)
        m.domains = rest; // patch 0010 format
    else
        return std::nullopt;
    if (m.domains.empty())
        return std::nullopt;
    return m;
}

inline std::wstring format_search_list_mark(const SearchListMark &m)
{
    return format_owner(m.owner) + L"|" + (m.snapshot_ours ? L"1" : L"0") + L"|" + m.domains;
}

/**
 * @brief Remove each of `domains` (comma separated) once from `list` (comma separated)
 *
 * Whole entries only ("a.com" never matches inside "aa.com"). The other entries keep their
 * order. Returns the shortened list, or nothing if one of the domains is not in the list.
 */
inline std::optional<std::wstring> remove_domains(const std::wstring &list, const std::wstring &domains)
{
    auto split = [](const std::wstring &s)
    {
        std::vector<std::wstring> v;
        std::wstring::size_type pos = 0;
        while (pos <= s.size() && !s.empty())
        {
            const auto comma = s.find(L',', pos);
            v.push_back(s.substr(pos, comma == std::wstring::npos ? std::wstring::npos : comma - pos));
            if (comma == std::wstring::npos)
                break;
            pos = comma + 1;
        }
        return v;
    };
    std::vector<std::wstring> entries = split(list);
    for (const auto &d : split(domains))
    {
        bool found = false;
        for (auto it = entries.begin(); it != entries.end(); ++it)
        {
            if (*it == d)
            {
                entries.erase(it);
                found = true;
                break;
            }
        }
        if (!found)
            return std::nullopt;
    }
    std::wstring out;
    for (const auto &e : entries)
    {
        if (!out.empty())
            out += L",";
        out += e;
    }
    return out;
}

// ---- NRPT rules: our rule ids end in "-<pid>"; the owner (with start time) is in the rule's
// documented "Comment" value as "UH VPN owner <owner>"

inline constexpr wchar_t nrpt_comment_prefix[] = L"UH VPN owner ";

inline std::wstring nrpt_comment(const Owner &o)
{
    return nrpt_comment_prefix + format_owner(o);
}

/**
 * @brief The owner of one of our NRPT rules, or nothing if it cannot be read
 *
 * The pid comes from the rule id. If the Comment names the same pid with a start time, that
 * start time is used; a rule without such a Comment (made before owner marks had start times)
 * has a pid only. A Comment that names another pid makes the rule unreadable.
 */
inline std::optional<Owner> parse_nrpt_owner(const std::wstring &rule_id, const std::wstring &comment)
{
    const auto dash = rule_id.rfind(L'-');
    if (dash == std::wstring::npos)
        return std::nullopt;
    auto o = parse_owner(rule_id.substr(dash + 1));
    if (!o || o->start)
        return std::nullopt;
    const std::wstring prefix = nrpt_comment_prefix;
    if (comment.compare(0, prefix.size(), prefix) == 0)
    {
        const auto c = parse_owner(comment.substr(prefix.size()));
        if (!c || c->pid != o->pid)
            return std::nullopt;
        return c;
    }
    return o;
}

} // namespace openvpn::OwnerMark
