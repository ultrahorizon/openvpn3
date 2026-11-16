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

#include <openvpn/win/ownermark.hpp>

using namespace openvpn::OwnerMark;

namespace {
const Owner self{100, 5000};
Probe none(std::uint32_t)
{
    return {};
}
} // namespace

TEST(OwnerMark, ParseOwner)
{
    EXPECT_EQ(parse_owner(L"42")->pid, 42u);
    EXPECT_FALSE(parse_owner(L"42")->start.has_value());
    EXPECT_EQ(*parse_owner(L"42:133456")->start, 133456u);
    EXPECT_FALSE(parse_owner(L"").has_value());
    EXPECT_FALSE(parse_owner(L"0").has_value());
    EXPECT_FALSE(parse_owner(L"abc").has_value());
    EXPECT_FALSE(parse_owner(L"42:").has_value());
    EXPECT_FALSE(parse_owner(L"42:x").has_value());
    EXPECT_FALSE(parse_owner(L"-1").has_value());
    EXPECT_FALSE(parse_owner(L"4294967296").has_value());
    EXPECT_EQ(format_owner(*parse_owner(L"42:7")), L"42:7");
}

TEST(OwnerMark, JudgeKeepsWhatItCannotRead)
{
    EXPECT_EQ(judge(std::nullopt, self, none), Verdict::Unreadable);
    EXPECT_EQ(judge(Owner{0, std::nullopt}, self, none), Verdict::Unreadable);
}

TEST(OwnerMark, JudgeOwnProcess)
{
    EXPECT_EQ(judge(Owner{100, 5000}, self, none), Verdict::Own);
    EXPECT_EQ(judge(Owner{100, std::nullopt}, self, none), Verdict::Own);
    // an earlier process had our id
    EXPECT_EQ(judge(Owner{100, 4000}, self, none), Verdict::Gone);
}

TEST(OwnerMark, JudgeOtherProcess)
{
    auto running_since = [](std::optional<std::uint64_t> start)
    { return [start](std::uint32_t) { return Probe{true, start}; }; };
    EXPECT_EQ(judge(Owner{7, 1000}, self, none), Verdict::Gone);                     // not running
    EXPECT_EQ(judge(Owner{7, 1000}, self, running_since(1000)), Verdict::Live);      // same process
    EXPECT_EQ(judge(Owner{7, 1000}, self, running_since(2000)), Verdict::Gone);      // id reused
    EXPECT_EQ(judge(Owner{7, 1000}, self, running_since(std::nullopt)), Verdict::Live); // cannot tell: keep
    EXPECT_EQ(judge(Owner{7, std::nullopt}, self, running_since(2000)), Verdict::Live); // old mark: keep
    EXPECT_EQ(judge(Owner{7, std::nullopt}, self, none), Verdict::Gone);
}

TEST(OwnerMark, SearchListMark)
{
    SearchListMark m;
    m.owner = Owner{7, 1000};
    m.snapshot_ours = true;
    m.domains = L"a.example,b.example";
    const auto v = format_search_list_mark(m);
    EXPECT_EQ(v, L"7:1000|1|a.example,b.example");
    const auto p = parse_search_list_mark(v);
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(p->owner.pid, 7u);
    EXPECT_EQ(*p->owner.start, 1000u);
    EXPECT_TRUE(p->snapshot_ours);
    EXPECT_EQ(p->domains, L"a.example,b.example");
    EXPECT_FALSE(parse_search_list_mark(L"7:1000|0|x").value().snapshot_ours);

    // patch 0010 marks: pid only, no snapshot flag
    const auto old = parse_search_list_mark(L"7|a.example");
    ASSERT_TRUE(old.has_value());
    EXPECT_FALSE(old->owner.start.has_value());
    EXPECT_FALSE(old->snapshot_ours);
    EXPECT_EQ(old->domains, L"a.example");

    for (const wchar_t *bad : {L"", L"garbage", L"|a", L"7|", L"7:1000|a.example", L"7:1000|2|a", L"7:1000|1|", L"x:1|1|a"})
        EXPECT_FALSE(parse_search_list_mark(bad).has_value()) << "accepted: " << bad;
}

TEST(OwnerMark, NrptOwner)
{
    EXPECT_EQ(nrpt_comment(Owner{7, 1000}), L"UH VPN owner 7:1000");
    const auto with = parse_nrpt_owner(L"UHVPNDNSRouting-7", L"UH VPN owner 7:1000");
    ASSERT_TRUE(with.has_value());
    EXPECT_EQ(*with->start, 1000u);
    const auto exclude = parse_nrpt_owner(L"UHVPNDNSRoutingX-2-7", L"UH VPN owner 7:1000");
    ASSERT_TRUE(exclude.has_value());
    EXPECT_EQ(exclude->pid, 7u);
    // a rule from before the Comment: pid only
    const auto old = parse_nrpt_owner(L"UHVPNDNSRouting-7", L"");
    ASSERT_TRUE(old.has_value());
    EXPECT_FALSE(old->start.has_value());
    // someone else's comment text is not ours to interpret: the rule id decides
    EXPECT_TRUE(parse_nrpt_owner(L"UHVPNDNSRouting-7", L"set by IT").has_value());
    // contradictions and garbage are unreadable
    EXPECT_FALSE(parse_nrpt_owner(L"UHVPNDNSRouting-7", L"UH VPN owner 8:1000").has_value());
    EXPECT_FALSE(parse_nrpt_owner(L"UHVPNDNSRouting-7", L"UH VPN owner 7:x").has_value());
    EXPECT_FALSE(parse_nrpt_owner(L"UHVPNDNSRouting-abc", L"").has_value());
    EXPECT_FALSE(parse_nrpt_owner(L"UHVPNDNSRouting", L"").has_value());
}

TEST(OwnerMark, RemoveDomains)
{
    EXPECT_EQ(*remove_domains(L"corp.example,a.example,b.example", L"a.example,b.example"), L"corp.example");
    EXPECT_EQ(*remove_domains(L"a.example", L"a.example"), L"");
    EXPECT_EQ(*remove_domains(L"x,a,y,b,z", L"a,b"), L"x,y,z");
    // whole entries only
    EXPECT_FALSE(remove_domains(L"aa.example", L"a.example").has_value());
    // all or nothing
    EXPECT_FALSE(remove_domains(L"a.example", L"a.example,b.example").has_value());
    // a duplicate is removed once
    EXPECT_EQ(*remove_domains(L"a,a", L"a"), L"a");
}
