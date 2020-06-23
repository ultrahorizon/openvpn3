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
#include <openvpn/win/cmd.hpp>

namespace openvpn::uhvpn {

bool OpenVPN3Cleanup::cleanup_nrpt(std::string &log)
{
    std::ostringstream ss;
    ::openvpn::TunWin::NRPT::ActionDelete delete_nrpt;
    delete_nrpt.execute(ss);

    auto flush_cmd = ::openvpn::WinCmd("ipconfig /flushdns");
    flush_cmd.execute(ss);

    log = ss.str();
    return true;
}

} // namespace openvpn::uhvpn
