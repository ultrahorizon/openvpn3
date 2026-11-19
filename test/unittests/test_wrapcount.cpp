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

#include "test_common.hpp"

#include <openvpn/dco/wrapcount.hpp>

using namespace openvpn;

TEST(WrapCount32, CountsUp)
{
    WrapCount32 c;
    EXPECT_EQ(c.update(0), 0u);
    EXPECT_EQ(c.update(5), 5u);
    EXPECT_EQ(c.update(5), 5u);
    EXPECT_EQ(c.update(1000), 1000u);
}

TEST(WrapCount32, WrapDoesNotGoBackwards)
{
    WrapCount32 c;
    EXPECT_EQ(c.update(0xfffffff0u), 0xfffffff0ull);
    // 0x20 more packets: the 32-bit counter wrapped to 0x10
    EXPECT_EQ(c.update(0x10u), 0x100000010ull);
    EXPECT_EQ(c.update(0x11u), 0x100000011ull);
    // a second wrap
    EXPECT_EQ(c.update(0xffffffffu), 0x1ffffffffull);
    EXPECT_EQ(c.update(0u), 0x200000000ull);
}

TEST(WrapCount32, SignedDriverValueReadUnsigned)
{
    // the driver's LONG (32-bit) goes from 0x7fffffff to negative: still counting up
    WrapCount32 c;
    const std::int32_t before = 0x7fffffff;
    const std::int32_t after = static_cast<std::int32_t>(0x80000002u);
    EXPECT_EQ(c.update(static_cast<std::uint32_t>(before)), 0x7fffffffull);
    EXPECT_EQ(c.update(static_cast<std::uint32_t>(after)), 0x80000002ull);
}

TEST(WrapCount32, ResetAddsWhatWasCountedSince)
{
    WrapCount32 c;
    EXPECT_EQ(c.update(1000), 1000u);
    // the driver zeroed its statistics and has counted 7 since
    EXPECT_EQ(c.update(7, true), 1007u);
    EXPECT_EQ(c.update(10), 1010u);
}
