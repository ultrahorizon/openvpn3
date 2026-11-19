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

// Windows tunnel adapter configuration actions (addresses, routes, interface
// metric, DNS servers, DNS cache flush) used by TunWin::Setup.
//
// By default each action calls the IP Helper API (or dnsapi) directly. Define
// OPENVPN_USE_NETSH to get the netsh / ipconfig commands openvpn3 used before,
// with exactly the same command lines. The IP Helper variants never start a
// process: each netsh call took about 0.1 s normally and, on a busy machine,
// up to 20 s.
//
// Failures are logged and do not throw, as with the netsh commands (whose exit
// status was never checked).

#pragma once

#include <openvpn/common/socktypes.hpp>

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <objbase.h> // IIDFromString

#include <string>
#include <sstream>
#include <vector>

#include <openvpn/common/action.hpp>
#include <openvpn/common/wstring.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/win/cmd.hpp>

namespace openvpn::TunWin::IpCfg {

// The action classes compile in both builds; with OPENVPN_USE_NETSH only the factories at the
// end change, and TunWin::Setup does not run ActionResetInterface.

namespace detail {
inline SOCKADDR_INET sockaddr_inet(const IP::Addr &addr)
{
    SOCKADDR_INET sa;
    ZeroMemory(&sa, sizeof(sa));
    if (addr.is_ipv6())
    {
        sa.si_family = AF_INET6;
        const IPv6::Addr a6 = addr.to_ipv6();
        a6.to_byte_string(sa.Ipv6.sin6_addr.u.Byte);
    }
    else
    {
        sa.si_family = AF_INET;
        sa.Ipv4.sin_addr.s_addr = htonl(addr.to_ipv4().to_uint32());
    }
    return sa;
}

inline SOCKADDR_INET unspecified(const ADDRESS_FAMILY af)
{
    SOCKADDR_INET sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.si_family = af;
    return sa;
}

inline void result(std::ostream &os, const DWORD err, const DWORD ok_too = NO_ERROR)
{
    if (err == NO_ERROR || err == ok_too)
        return;
    os << "IPHelper: error " << err << "\n";
}

// System32 module function, nullptr when the running Windows does not have it.
template <typename F>
inline F system_function(const wchar_t *module, const char *name)
{
    HMODULE h = ::LoadLibraryExW(module, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!h)
        return nullptr;
    // never freed: the module stays loaded for the life of the process, like iphlpapi itself
    return reinterpret_cast<F>(::GetProcAddress(h, name));
}
} // namespace detail

// Add or delete a route. nexthop empty: on-link (unspecified next hop).
class ActionRoute : public Action
{
  public:
    ActionRoute(const std::string &dest, const unsigned int prefix_len, const DWORD iface_index,
                const std::string &nexthop, const int metric, const bool add)
        : add_(add)
    {
        // netsh accepted a destination with host bits set (e.g. "fe80::1/64", from
        // ifconfig-ipv6); CreateIpForwardEntry2 refuses it (87): use the network address
        const IP::Addr d = IP::Addr::from_string(dest).network_addr(prefix_len);
        InitializeIpForwardEntry(&row_);
        row_.InterfaceIndex = iface_index;
        row_.DestinationPrefix.Prefix = detail::sockaddr_inet(d);
        row_.DestinationPrefix.PrefixLength = static_cast<UINT8>(prefix_len);
        row_.NextHop = nexthop.empty() ? detail::unspecified(row_.DestinationPrefix.Prefix.si_family)
                                       : detail::sockaddr_inet(IP::Addr::from_string(nexthop));
        // netsh's default route metric is 256 for both families
        row_.Metric = metric >= 0 ? static_cast<ULONG>(metric) : 256;
        row_.Protocol = static_cast<NL_ROUTE_PROTOCOL>(MIB_IPPROTO_NETMGMT);

        std::ostringstream o;
        o << "IPHelper: " << (add ? "add" : "delete") << " route " << dest << '/' << prefix_len
          << " if=" << iface_index << " via " << (nexthop.empty() ? "on-link" : nexthop);
        if (add)
            o << " metric=" << row_.Metric;
        desc_ = o.str();
    }

    void execute(std::ostream &os) override
    {
        os << desc_ << "\n";
        if (add_)
            detail::result(os, CreateIpForwardEntry2(&row_), ERROR_OBJECT_ALREADY_EXISTS);
        else
            detail::result(os, DeleteIpForwardEntry2(&row_), ERROR_NOT_FOUND);
    }

    std::string to_string() const override
    {
        return desc_;
    }

  private:
    MIB_IPFORWARD_ROW2 row_;
    const bool add_;
    std::string desc_;
};

// Delete one route, given as read from GetIpForwardTable2.
class ActionDeleteRouteRow : public Action
{
  public:
    explicit ActionDeleteRouteRow(const MIB_IPFORWARD_ROW2 &row, const std::string &desc)
        : row_(row), desc_("IPHelper: delete route " + desc + " if=" + std::to_string(row.InterfaceIndex))
    {
    }

    void execute(std::ostream &os) override
    {
        os << desc_ << "\n";
        detail::result(os, DeleteIpForwardEntry2(&row_), ERROR_NOT_FOUND);
    }

    std::string to_string() const override
    {
        return desc_;
    }

  private:
    const MIB_IPFORWARD_ROW2 row_;
    const std::string desc_;
};

// openvpn3's block-ipv6 routes (2000::/4, 3000::/4, fc00::/7 on the loopback interface) are
// shared ground: stock openvpn3 clients add exactly the same routes, and Windows keys a route
// by prefix, interface and next hop, not by metric. Ours carry a metric no stock client uses
// (stock: 256), so that our teardown and our crash cleanup remove only routes this fork added:
// a route that already existed when we wanted to add it is another client's and stays.
inline constexpr ULONG BLOCK_IPV6_METRIC = 4181;
inline constexpr DWORD BLOCK_IPV6_IFINDEX = 1; // loopback, as openvpn3 has always used

struct BlockIpv6Net
{
    const char *net;
    unsigned int prefix_len;
};
inline constexpr BlockIpv6Net block_ipv6_nets[] = {{"2000::", 4}, {"3000::", 4}, {"fc00::", 7}};

// The route row of one of our block-ipv6 routes.
inline MIB_IPFORWARD_ROW2 block_ipv6_row(const std::string &net, const unsigned int prefix_len)
{
    MIB_IPFORWARD_ROW2 row;
    InitializeIpForwardEntry(&row);
    row.InterfaceIndex = BLOCK_IPV6_IFINDEX;
    row.DestinationPrefix.Prefix = detail::sockaddr_inet(IP::Addr::from_string(net));
    row.DestinationPrefix.PrefixLength = static_cast<UINT8>(prefix_len);
    row.NextHop = detail::unspecified(AF_INET6);
    row.Metric = BLOCK_IPV6_METRIC;
    row.Protocol = static_cast<NL_ROUTE_PROTOCOL>(MIB_IPPROTO_NETMGMT);
    return row;
}

// Whether a route row (as a change notification gives it) is one of the block-ipv6 routes:
// one of the three prefixes, on the loopback interface, on-link. Any metric.
inline const BlockIpv6Net *block_ipv6_net_of(const MIB_IPFORWARD_ROW2 &row)
{
    if (row.InterfaceIndex != BLOCK_IPV6_IFINDEX || row.DestinationPrefix.Prefix.si_family != AF_INET6)
        return nullptr;
    static const IN6_ADDR any = {};
    if (::memcmp(&row.NextHop.Ipv6.sin6_addr, &any, sizeof(any)) != 0)
        return nullptr;
    for (const auto &n : block_ipv6_nets)
    {
        const MIB_IPFORWARD_ROW2 ours = block_ipv6_row(n.net, n.prefix_len);
        if (row.DestinationPrefix.PrefixLength == ours.DestinationPrefix.PrefixLength
            && ::memcmp(&row.DestinationPrefix.Prefix.Ipv6.sin6_addr, &ours.DestinationPrefix.Prefix.Ipv6.sin6_addr, sizeof(IN6_ADDR)) == 0)
            return &n;
    }
    return nullptr;
}

class ActionBlockIpv6Route : public Action
{
  public:
    ActionBlockIpv6Route(const std::string &net, const unsigned int prefix_len, const bool add)
        : row_(block_ipv6_row(net, prefix_len)), add_(add)
    {
        desc_ = "block-ipv6 route " + net + '/' + std::to_string(prefix_len) + " if="
                + std::to_string(BLOCK_IPV6_IFINDEX) + " metric=" + std::to_string(BLOCK_IPV6_METRIC);
    }

    // add: log it, and say so if the route was there already (not ours: left to its owner).
    // delete: silent if absent; removes it only if it carries our metric.
    void execute(std::ostream &os) override
    {
        if (add_)
        {
            os << "IPHelper: add " << desc_ << "\n";
            const DWORD err = CreateIpForwardEntry2(&row_);
            if (err == ERROR_OBJECT_ALREADY_EXISTS)
                os << "IPHelper: block-ipv6 route exists already (another client's), left to it\n";
            else
                detail::result(os, err);
            return;
        }
        MIB_IPFORWARD_ROW2 cur = row_;
        if (GetIpForwardEntry2(&cur) != NO_ERROR)
            return;
        if (cur.Metric != BLOCK_IPV6_METRIC)
        {
            os << "IPHelper: " << desc_ << ": present with metric " << cur.Metric << " (not ours), left alone\n";
            return;
        }
        os << "IPHelper: remove " << desc_ << "\n";
        detail::result(os, DeleteIpForwardEntry2(&cur), ERROR_NOT_FOUND);
    }

    std::string to_string() const override
    {
        return std::string("IPHelper: ") + (add_ ? "add " : "delete ") + desc_;
    }

  private:
    MIB_IPFORWARD_ROW2 row_;
    const bool add_;
    std::string desc_;
};

// Interface metric for one address family (automatic metric off).
class ActionInterfaceMetric : public Action
{
  public:
    ActionInterfaceMetric(const DWORD iface_index, const ADDRESS_FAMILY af, const ULONG metric)
        : index_(iface_index), af_(af), metric_(metric)
    {
    }

    void execute(std::ostream &os) override
    {
        os << to_string() << "\n";
        MIB_IPINTERFACE_ROW row;
        InitializeIpInterfaceEntry(&row);
        row.InterfaceIndex = index_;
        row.Family = af_;
        DWORD err = GetIpInterfaceEntry(&row);
        if (err == NO_ERROR)
        {
            row.UseAutomaticMetric = FALSE;
            row.Metric = metric_;
            if (af_ == AF_INET)
                row.SitePrefixLength = 0; // must be 0 for IPv4 in SetIpInterfaceEntry
            err = SetIpInterfaceEntry(&row);
        }
        detail::result(os, err);
    }

    std::string to_string() const override
    {
        return "IPHelper: set interface if=" + std::to_string(index_) + (af_ == AF_INET6 ? " ipv6" : " ipv4")
               + " metric=" + std::to_string(metric_);
    }

  private:
    const DWORD index_;
    const ADDRESS_FAMILY af_;
    const ULONG metric_;
};

// Add or delete a unicast address. On add with replace_family, first remove the
// interface's other addresses of that family, link-local (APIPA) included: what
// "netsh interface ip set address ... static" does.
class ActionAddress : public Action
{
  public:
    ActionAddress(const DWORD iface_index, const std::string &addr, const unsigned int prefix_len,
                  const bool add, const bool replace_family = false)
        : add_(add), replace_(replace_family)
    {
        InitializeUnicastIpAddressEntry(&row_);
        row_.InterfaceIndex = iface_index;
        row_.Address = detail::sockaddr_inet(IP::Addr::from_string(addr));
        row_.OnLinkPrefixLength = static_cast<UINT8>(prefix_len);
        desc_ = std::string("IPHelper: ") + (add ? "add" : "delete") + " address " + addr + '/'
                + std::to_string(prefix_len) + " if=" + std::to_string(iface_index);
    }

    void execute(std::ostream &os) override
    {
        os << desc_ << "\n";
        if (!add_)
        {
            detail::result(os, DeleteUnicastIpAddressEntry(&row_), ERROR_NOT_FOUND);
            return;
        }
        if (replace_)
            remove_others(os);
        DWORD err = CreateUnicastIpAddressEntry(&row_);
        if (err == ERROR_OBJECT_ALREADY_EXISTS)
            err = SetUnicastIpAddressEntry(&row_);
        detail::result(os, err);
    }

    std::string to_string() const override
    {
        return desc_;
    }

  private:
    void remove_others(std::ostream &os) const
    {
        PMIB_UNICASTIPADDRESS_TABLE table = nullptr;
        if (GetUnicastIpAddressTable(row_.Address.si_family, &table) != NO_ERROR)
            return;
        const IP::Addr want = from_sockaddr(row_.Address);
        for (ULONG i = 0; i < table->NumEntries; ++i)
        {
            const MIB_UNICASTIPADDRESS_ROW &r = table->Table[i];
            if (r.InterfaceIndex != row_.InterfaceIndex)
                continue;
            const IP::Addr a = from_sockaddr(r.Address);
            if (a == want)
                continue;
            os << "IPHelper: remove stale address " << a.to_string() << " if=" << r.InterfaceIndex << "\n";
            detail::result(os, DeleteUnicastIpAddressEntry(&r), ERROR_NOT_FOUND);
        }
        FreeMibTable(table);
    }

    static IP::Addr from_sockaddr(const SOCKADDR_INET &sa)
    {
        if (sa.si_family == AF_INET6)
            return IP::Addr::from_ipv6(IPv6::Addr::from_byte_string(sa.Ipv6.sin6_addr.u.Byte));
        return IP::Addr::from_ipv4(IPv4::Addr::from_uint32(ntohl(sa.Ipv4.sin_addr.s_addr)));
    }

    MIB_UNICASTIPADDRESS_ROW row_;
    const bool add_;
    const bool replace_;
    std::string desc_;
};

// Static DNS servers of one family on an interface (empty list: none), through
// SetInterfaceDnsSettings (Windows 10 2004 and later). Older Windows: the netsh
// commands, as before.
class ActionDnsServers : public Action
{
  public:
    ActionDnsServers(const GUID &iface_guid, const std::string &iface_index_name, const bool ipv6,
                     const std::vector<std::string> &servers)
        : guid_(iface_guid), index_name_(iface_index_name), ipv6_(ipv6), servers_(servers)
    {
    }

    void execute(std::ostream &os) override
    {
        os << to_string() << "\n";
        static const auto set_dns = detail::system_function<set_fn_t>(L"iphlpapi.dll", "SetInterfaceDnsSettings");
        if (!set_dns)
        {
            os << "IPHelper: SetInterfaceDnsSettings not available, using netsh\n";
            netsh(os);
            return;
        }
        std::wstring list;
        for (const auto &s : servers_)
        {
            if (!list.empty())
                list += L',';
            list += wstring::from_utf8(s);
        }
        Settings st{};
        st.Version = 1; // DNS_INTERFACE_SETTINGS_VERSION1
        st.Flags = DNS_SETTING_NAMESERVER_ | (ipv6_ ? DNS_SETTING_IPV6_ : 0);
        st.NameServer = const_cast<wchar_t *>(list.c_str());
        if (!servers_.empty())
        {
            // "register=primary": register the addresses, not the connection-specific name
            st.Flags |= DNS_SETTING_REGISTRATION_ENABLED_ | DNS_SETTING_REGISTER_ADAPTER_NAME_;
            st.RegistrationEnabled = 1;
            st.RegisterAdapterName = 0;
        }
        detail::result(os, set_dns(guid_, &st));
    }

    std::string to_string() const override
    {
        std::string s = std::string("IPHelper: set ") + (ipv6_ ? "ipv6" : "ipv4") + " dns servers if=" + index_name_ + " [";
        for (size_t i = 0; i < servers_.size(); ++i)
            s += (i ? "," : "") + servers_[i];
        return s + "]";
    }

  private:
    // DNS_INTERFACE_SETTINGS (netioapi.h, SDK 10.0.19041+), declared here so older SDKs build
    struct Settings
    {
        ULONG Version;
        ULONG64 Flags;
        PWSTR Domain;
        PWSTR NameServer;
        PWSTR SearchList;
        ULONG RegistrationEnabled;
        ULONG RegisterAdapterName;
        ULONG EnableLLMNR;
        ULONG QueryAdapterName;
        PWSTR ProfileNameServer;
    };
    static constexpr ULONG64 DNS_SETTING_IPV6_ = 0x0001;
    static constexpr ULONG64 DNS_SETTING_NAMESERVER_ = 0x0002;
    static constexpr ULONG64 DNS_SETTING_REGISTRATION_ENABLED_ = 0x0008;
    static constexpr ULONG64 DNS_SETTING_REGISTER_ADAPTER_NAME_ = 0x0010;
    using set_fn_t = DWORD(WINAPI *)(GUID, const Settings *);

    void netsh(std::ostream &os) const
    {
        const std::string proto = ipv6_ ? "ipv6" : "ip";
        if (servers_.empty())
        {
            WinCmd("netsh interface " + proto + " delete dnsservers " + index_name_ + " all validate=no").execute(os);
            return;
        }
        for (size_t i = 0; i < servers_.size(); ++i)
        {
            if (i)
                WinCmd("netsh interface " + proto + " add dnsservers " + index_name_ + ' ' + servers_[i] + ' ' + std::to_string(i + 1) + " validate=no").execute(os);
            else
                WinCmd("netsh interface " + proto + " set dnsservers " + index_name_ + " static " + servers_[i] + " register=primary validate=no").execute(os);
        }
    }

    const GUID guid_;
    const std::string index_name_;
    const bool ipv6_;
    const std::vector<std::string> servers_;
};

// Flush the DNS resolver cache (what "ipconfig /flushdns" does).
class ActionFlushDns : public Action
{
  public:
    void execute(std::ostream &os) override
    {
        os << to_string() << "\n";
        using flush_fn_t = BOOL(WINAPI *)();
        static const auto flush = detail::system_function<flush_fn_t>(L"dnsapi.dll", "DnsFlushResolverCache");
        if (!flush)
        {
            WinCmd("ipconfig /flushdns").execute(os);
            return;
        }
        if (!flush())
            os << "DnsFlushResolverCache failed: error " << ::GetLastError() << "\n";
    }

    std::string to_string() const override
    {
        return "DnsFlushResolverCache";
    }
};

// Undo, on one adapter, what an earlier session that never reached its teardown (a crash, a
// killed process) can have left: static DNS servers of both address families, manually added
// unicast addresses of both families, and the connection-specific DNS suffix ("Domain"). Run
// at the start of tunnel setup, before anything is configured, and by crash cleanup. Without
// it, a session that pushes only IPv4 DNS servers kept a stale IPv6 DNS server from an
// earlier one. Routes on the adapter are removed by Util::ActionDeleteAllRoutesOnInterface.
// Only for a VPN adapter: it must never be pointed at another interface.
class ActionResetInterface : public Action
{
  public:
    ActionResetInterface(const DWORD iface_index, const std::string &iface_guid)
        : index_(iface_index), guid_str_(iface_guid)
    {
    }

    void execute(std::ostream &os) override
    {
        os << to_string() << "\n";
        for (const ADDRESS_FAMILY af : {AF_INET, AF_INET6})
            remove_manual_addresses(os, af);
        GUID guid;
        if (guid_str_.empty() || ::IIDFromString(wstring::from_utf8(guid_str_).c_str(), &guid) != S_OK)
        {
            os << "IPHelper: reset: adapter GUID '" << guid_str_ << "' not usable, DNS settings left alone\n";
            return;
        }
        const std::string index_name = std::to_string(index_);
        for (const bool ipv6 : {false, true})
        {
            if (registry_value_set(ipv6 ? "Tcpip6" : "Tcpip", L"NameServer"))
                os << "IPHelper: clear stale " << (ipv6 ? "ipv6" : "ipv4") << " DNS servers\n";
            ActionDnsServers(guid, index_name, ipv6, {}).execute(os);
        }
        clear_domain_suffix(os);
    }

    std::string to_string() const override
    {
        return "IPHelper: reset interface if=" + std::to_string(index_) + " " + guid_str_
               + " (manual addresses, DNS servers, DNS suffix)";
    }

  private:
    void remove_manual_addresses(std::ostream &os, const ADDRESS_FAMILY af) const
    {
        PMIB_UNICASTIPADDRESS_TABLE table = nullptr;
        if (GetUnicastIpAddressTable(af, &table) != NO_ERROR)
            return;
        for (ULONG i = 0; i < table->NumEntries; ++i)
        {
            const MIB_UNICASTIPADDRESS_ROW &r = table->Table[i];
            if (r.InterfaceIndex != index_ || r.PrefixOrigin != IpPrefixOriginManual)
                continue;
            os << "IPHelper: remove stale address if=" << index_ << (af == AF_INET6 ? " ipv6" : " ipv4") << "\n";
            detail::result(os, DeleteUnicastIpAddressEntry(&r), ERROR_NOT_FOUND);
        }
        FreeMibTable(table);
    }

    // A non-empty string value under Tcpip(6)\Parameters\Interfaces\{guid} (where the static
    // DNS servers set by SetInterfaceDnsSettings or netsh are kept, as "NameServer")
    bool registry_value_set(const char *svc, const wchar_t *value) const
    {
        const std::string name = std::string("SYSTEM\\CurrentControlSet\\Services\\") + svc
                                 + "\\Parameters\\Interfaces\\" + guid_str_;
        HKEY key;
        if (::RegOpenKeyExA(HKEY_LOCAL_MACHINE, name.c_str(), 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS)
            return false;
        DWORD type = 0, size = 0;
        const LSTATUS q = ::RegQueryValueExW(key, value, nullptr, &type, nullptr, &size);
        ::RegCloseKey(key);
        return q == ERROR_SUCCESS && size > sizeof(wchar_t);
    }

    // Tcpip\Parameters\Interfaces\{guid}\Domain: what DNS::set_itf_domain_suffix and
    // Util::ActionSetAdapterDomainSuffix write for a pushed adapter domain suffix (our adapters
    // have DHCP off, so never DhcpDomain)
    void clear_domain_suffix(std::ostream &os) const
    {
        const std::string name = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\" + guid_str_;
        HKEY key;
        if (::RegOpenKeyExA(HKEY_LOCAL_MACHINE, name.c_str(), 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &key) != ERROR_SUCCESS)
            return;
        DWORD type = 0, size = 0;
        const LSTATUS q = ::RegQueryValueExW(key, L"Domain", nullptr, &type, nullptr, &size);
        if (q == ERROR_SUCCESS && size > sizeof(wchar_t))
        {
            os << "IPHelper: clear stale DNS suffix\n";
            const wchar_t empty[] = L"";
            const LSTATUS w = ::RegSetValueExW(key, L"Domain", 0, REG_SZ, reinterpret_cast<const BYTE *>(empty), sizeof(empty));
            if (w != ERROR_SUCCESS)
                os << "IPHelper: error " << w << "\n";
        }
        ::RegCloseKey(key);
    }

    const DWORD index_;
    const std::string guid_str_;
};

// ---- factories used by TunWin::Setup: one call per former netsh command line

// "netsh interface ip[v6] add|delete route DEST/PL IFACE [NEXTHOP] [metric=M] store=active".
// iface_arg is the netsh interface argument (index, name, or "interface=1").
inline Action *route(const std::string &dest, const unsigned int prefix_len, const DWORD iface_index,
                     const std::string &iface_arg, const std::string &nexthop, const int metric, const bool add)
{
#ifdef OPENVPN_USE_NETSH
    const bool v6 = IP::Addr::from_string(dest).is_ipv6();
    std::string cmd = std::string("netsh interface ") + (v6 ? "ipv6" : "ip") + (add ? " add" : " delete") + " route "
                      + dest + '/' + std::to_string(prefix_len) + ' ' + iface_arg;
    if (!nexthop.empty())
        cmd += ' ' + nexthop;
    if (add && metric >= 0)
        cmd += " metric=" + std::to_string(metric);
    return new WinCmd(cmd + " store=active");
#else
    return new ActionRoute(dest, prefix_len, iface_index, nexthop, metric, add);
#endif
}

// "netsh interface ipv6 add|delete route NET interface=1 store=active" (block-ipv6).
inline Action *block_ipv6_route(const BlockIpv6Net &n, const bool add)
{
#ifdef OPENVPN_USE_NETSH
    return route(n.net, n.prefix_len, BLOCK_IPV6_IFINDEX, "interface=1", "", -1, add);
#else
    return new ActionBlockIpv6Route(n.net, n.prefix_len, add);
#endif
}

// "netsh interface ip set interface IFACE metric=M" (IPv4).
inline Action *interface_metric4(const DWORD iface_index, const std::string &iface_arg, const ULONG metric)
{
#ifdef OPENVPN_USE_NETSH
    return new WinCmd("netsh interface ip set interface " + iface_arg + " metric=" + std::to_string(metric));
#else
    return new ActionInterfaceMetric(iface_index, AF_INET, metric);
#endif
}

// "netsh interface ip set address IFACE static ADDR MASK gateway=GW [gwmetric=M] store=active":
// the address replaces the interface's other IPv4 addresses, and a default route via the
// gateway is added (Setup deletes it again a few seconds later).
inline void set_address4(ActionList &create, const DWORD iface_index, const std::string &iface_arg,
                         const std::string &addr, const unsigned int prefix_len, const std::string &gateway, const int gwmetric)
{
#ifdef OPENVPN_USE_NETSH
    const std::string netmask = IPv4::Addr::netmask_from_prefix_len(prefix_len).to_string();
    const std::string metric = gwmetric >= 0 ? " gwmetric=" + std::to_string(gwmetric) : "";
    create.add(new WinCmd("netsh interface ip set address " + iface_arg + " static " + addr + ' ' + netmask + " gateway=" + gateway + metric + " store=active"));
#else
    create.add(new ActionAddress(iface_index, addr, prefix_len, true, true));
    // netsh's gateway route: metric gwmetric, else automatic (0)
    create.add(new ActionRoute("0.0.0.0", 0, iface_index, gateway, gwmetric >= 0 ? gwmetric : 0, true));
#endif
}

// "netsh interface ip delete address IFACE ADDR gateway=all store=active".
inline void delete_address4(ActionList &destroy, const DWORD iface_index, const std::string &iface_arg,
                            const std::string &addr, const unsigned int prefix_len, const std::string &gateway)
{
#ifdef OPENVPN_USE_NETSH
    destroy.add(new WinCmd("netsh interface ip delete address " + iface_arg + ' ' + addr + " gateway=all store=active"));
#else
    destroy.add(new ActionAddress(iface_index, addr, prefix_len, false));
    destroy.add(new ActionRoute("0.0.0.0", 0, iface_index, gateway, -1, false));
#endif
}

// "netsh interface ipv6 set|delete address IFACE ADDR store=active" (netsh makes it a /64).
inline Action *address6(const DWORD iface_index, const std::string &iface_arg, const std::string &addr,
                        const unsigned int prefix_len, const bool add)
{
#ifdef OPENVPN_USE_NETSH
    return new WinCmd(std::string("netsh interface ipv6 ") + (add ? "set" : "delete") + " address " + iface_arg + ' ' + addr + " store=active");
#else
    return new ActionAddress(iface_index, addr, prefix_len, add);
#endif
}

// "ipconfig /flushdns".
inline Action *flush_dns()
{
#ifdef OPENVPN_USE_NETSH
    return new WinCmd("ipconfig /flushdns");
#else
    return new ActionFlushDns();
#endif
}

} // namespace openvpn::TunWin::IpCfg
