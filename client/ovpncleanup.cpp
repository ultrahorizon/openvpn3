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
#include <openvpn/win/scoped_handle.hpp>
#include <openvpn/common/string.hpp>

namespace openvpn::uhvpn {

bool OpenVPN3Cleanup::cleanup_nrpt(std::string &log)
{
    std::ostringstream ss;
    // Only rules carrying our prefix whose owner (pid and start time, in the rule's Comment)
    // has ended; rules of a running owner and rules we cannot read stay, and rules without
    // our prefix are never looked at.
    const unsigned int n = ::openvpn::TunWin::NRPT::delete_stale_rules(::GetCurrentProcessId(), &ss);
    ss << "NRPT: removed " << n << " stale rule(s) of ended UH VPN sessions\n";

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

// Opens the ovpn-dco device of the adapter with this interface GUID the way a session does
// (exclusive, no sharing). found: the adapter has an ovpn-dco device interface (present and
// started); if so and the open fails, err is why.
static HANDLE open_dco_device(const std::string &adapter_guid, bool &found, DWORD &err)
{
    using namespace ::openvpn::TunWin;
    found = false;
    err = 0;
    const Util::DeviceInstanceIdInterfaceList list;
    for (const auto &e : list)
    {
        if (::openvpn::string::strcasecmp(e.net_cfg_instance_id, adapter_guid.c_str()) != 0
            || !e.device_interface.ends_with(Util::OVPNDCO_DEV_INTERFACE_REF_STRING))
            continue;
        found = true;
        const HANDLE h = ::CreateFileA(e.device_interface.c_str(),
                                       GENERIC_READ | GENERIC_WRITE,
                                       0,
                                       nullptr,
                                       OPEN_EXISTING,
                                       FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
                                       nullptr);
        if (h == INVALID_HANDLE_VALUE)
            err = ::GetLastError();
        return h;
    }
    return INVALID_HANDLE_VALUE;
}

OpenVPN3Cleanup::AdapterCleanup OpenVPN3Cleanup::cleanup_adapter(const std::string &adapter_guid, std::string &log)
{
    using namespace ::openvpn::TunWin;
    // before anything else: never touch an interface that is not a UH VPN adapter
    if (adapter_guid.empty() || !is_uh_vpn_adapter(adapter_guid))
    {
        log = "refused: '" + adapter_guid + "' is not a UH VPN adapter (no IsUHVPNAdapter marker); nothing changed";
        return AdapterCleanup::Refused;
    }
    // A session holds its ovpn-dco device open for as long as it runs: if we cannot open it,
    // someone is using the adapter (OpenVPN 2.6 or OpenVPN Connect may have taken it as the
    // first free ovpn-dco adapter) and its configuration is theirs. Held until we are done, so
    // nobody starts on it mid-reset. An adapter with no ovpn-dco device interface (another
    // driver, or not started) cannot be in use this way.
    bool found = false;
    DWORD open_err = 0;
    ::openvpn::Win::ScopedHANDLE device(open_dco_device(adapter_guid, found, open_err));
    if (found && !device.defined())
    {
        log = "in use: the ovpn-dco device of adapter " + adapter_guid + " is open (error "
              + std::to_string(open_err) + "); nothing changed";
        return AdapterCleanup::InUse;
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
        return AdapterCleanup::Refused;
    }

    // what a session's teardown would have undone on the adapter
    if (device.defined())
        ss << "opened the ovpn-dco device of adapter " << adapter_guid << " (not in use)\n";
    IpCfg::ActionResetInterface(index, adapter_guid).execute(ss);
    Util::ActionDeleteAllRoutesOnInterface(index).execute(ss);

    log = ss.str();
    return AdapterCleanup::Done;
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
