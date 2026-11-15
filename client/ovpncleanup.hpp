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

    // Undo what a session that never reached its teardown left on the UH VPN adapter with
    // this interface GUID ("{...}"): addresses, DNS servers of both families, DNS suffix,
    // routes. Run it only while no session runs. Refuses (false, nothing changed, why in log)
    // an adapter without the IsUHVPNAdapter marker or a GUID that names no interface.
    static bool cleanup_adapter(const std::string &adapter_guid, std::string &log);

    // Remove the block-ipv6 routes a UH VPN session added and never removed: only routes
    // with this fork's metric (stock openvpn3 clients add the same prefixes). log says what
    // was removed or left alone, and is empty if there was nothing.
    static bool cleanup_block_ipv6_routes(std::string &log);

    // Remove the DNS search domains a UH VPN session added and never removed: only if this
    // fork's owner value is present and its process is gone. log as above.
    static bool cleanup_search_domains(std::string &log);
};

} // namespace openvpn::uhvpn
