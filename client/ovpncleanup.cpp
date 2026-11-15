#include "ovpncleanup.hpp"

#include <sstream>

// Force ASIO to be included first - If Windows.h is defined first, ASIO gets a
// bit upset with us.
#include <openvpn/io/io.hpp>

// Set up OpenVPN log settings.  This isn't really used, but is required due to
// imports within openvpn/tun/win/nrpt.hpp.
#ifndef OPENVPN_LOG
#include <openvpn/log/logsimple.hpp>    // should be included early
#endif

// Finally, the headers we actually need!
#include <openvpn/tun/win/nrpt.hpp>
#include <openvpn/tun/win/dns.hpp>
#include <openvpn/tun/win/ipcfg.hpp>
#include <openvpn/tun/win/tunutil.hpp>

namespace openvpn::uhvpn {

bool OpenVPN3Cleanup::cleanup_nrpt(std::string &log)
{
    std::ostringstream ss;
    // Process id 0 removes every rule carrying our prefix, regardless of
    // which process created it.
    ::openvpn::TunWin::NRPT::ActionDelete delete_nrpt(0);
    delete_nrpt.execute(ss);

    ::openvpn::Action::Ptr flush_cmd(::openvpn::TunWin::IpCfg::flush_dns());
    flush_cmd->execute(ss);

    log = ss.str();
    return true;
}

// The adapter with this interface GUID carries the IsUHVPNAdapter marker (any of the three
// drivers). Registry reads only.
static bool is_uh_vpn_adapter(const std::string &adapter_guid)
{
    using namespace ::openvpn::TunWin;
    for (const Type t : {Type::TapWindows6, Type::Wintun, Type::OvpnDco})
    {
        try
        {
            if (!Util::tap_guids(t, adapter_guid).empty())
                return true;
        }
        catch (const std::exception &)
        {
        }
    }
    return false;
}

bool OpenVPN3Cleanup::cleanup_adapter(const std::string &adapter_guid, std::string &log)
{
    using namespace ::openvpn::TunWin;
    // before anything else: never touch an interface that is not a UH VPN adapter
    if (adapter_guid.empty() || !is_uh_vpn_adapter(adapter_guid))
    {
        log = "refused: '" + adapter_guid + "' is not a UH VPN adapter (no IsUHVPNAdapter marker); nothing changed";
        return false;
    }
    std::ostringstream ss;
    GUID guid;
    NET_LUID luid;
    NET_IFINDEX index = 0;
    if (adapter_guid.empty()
        || ::IIDFromString(wstring::from_utf8(adapter_guid).c_str(), &guid) != S_OK
        || ::ConvertInterfaceGuidToLuid(&guid, &luid) != NO_ERROR
        || ::ConvertInterfaceLuidToIndex(&luid, &index) != NO_ERROR)
    {
        log = "no interface for adapter GUID '" + adapter_guid + "'";
        return false;
    }

    // what a session's teardown would have undone on the adapter
    IpCfg::ActionResetInterface(index, adapter_guid).execute(ss);
    Util::ActionDeleteAllRoutesOnInterface(index).execute(ss);

    log = ss.str();
    return true;
}

bool OpenVPN3Cleanup::cleanup_block_ipv6_routes(std::string &log)
{
    using namespace ::openvpn::TunWin;
    std::ostringstream ss;
    for (const auto &n : IpCfg::block_ipv6_nets)
        IpCfg::ActionBlockIpv6Route(n.net, n.prefix_len, false).execute(ss);
    log = ss.str();
    return true;
}

bool OpenVPN3Cleanup::cleanup_search_domains(std::string &log)
{
    std::ostringstream ss;
    ::openvpn::TunWin::DNS::remove_stale_search_domains(ss);
    log = ss.str();
    return true;
}

} // namespace openvpn::uhvpn
