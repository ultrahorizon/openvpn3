#pragma once

#include <string>

namespace openvpn::uhvpn {

// Helper methods for cleaning up OpenVPN 3 state that make use of OpenVPN 3
// internals and thus are implemented within the OpenVPN 3 project so they can
// make use of the appropriate build settings.
class OpenVPN3Cleanup {
public:
    // This class only provides static utility functions and thus does not need
    // to be constructed.
    OpenVPN3Cleanup() = delete;

    static bool cleanup_nrpt(std::string &log);

    // Undo what a session that never reached its teardown left on the VPN adapter with this
    // interface GUID ("{...}"): addresses, DNS servers of both families, DNS suffix, routes;
    // also openvpn3's block-ipv6 routes and a changed DNS search list. Run it only while no
    // session runs, and only for a UH VPN adapter. false (and why in log) if the GUID names
    // no interface.
    static bool cleanup_adapter(const std::string &adapter_guid, std::string &log);
};

} // namespace openvpn::uhvpn
