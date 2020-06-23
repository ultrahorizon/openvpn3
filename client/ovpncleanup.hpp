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
};

} // namespace openvpn::uhvpn
