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

#include <cstdint>

namespace openvpn {

/**
 * @brief A 64-bit total kept from a 32-bit counter that wraps
 *
 * ovpn-dco-win reports its packet counters as 32-bit LONGs, which wrap after 2^32 packets
 * (read unsigned). Fed every reading, this keeps a total that never goes backwards: a
 * reading below the previous one is a wrap, unless the caller says the source was zeroed
 * (then the reading is what was counted since). One wrap between two readings at most can
 * be seen; with readings at least every few minutes that cannot be missed.
 */
class WrapCount32
{
  public:
    /**
     * @param raw    the counter's current value
     * @param reset  the source counter was zeroed since the previous reading
     * @return       the total so far
     */
    std::uint64_t update(const std::uint32_t raw, const bool reset = false)
    {
        total_ += reset ? raw : static_cast<std::uint32_t>(raw - last_);
        last_ = raw;
        return total_;
    }

    std::uint64_t total() const
    {
        return total_;
    }

  private:
    std::uint32_t last_ = 0;
    std::uint64_t total_ = 0;
};

} // namespace openvpn
