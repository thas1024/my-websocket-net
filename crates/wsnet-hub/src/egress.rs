//! Public-egress address policy (DESIGN.md section 9.3).
//!
//! Section 9.3 requires the Hub's public egress to refuse loopback, private,
//! link-local, unique-local, unspecified, broadcast, and cloud-metadata
//! addresses by default, and to exempt one only when an explicit allowlist rule
//! names it. It also fixes *when* that check may run: a name is resolved once,
//! every candidate address is classified, and only an address that already
//! passed is connected to, so a DNS rebind cannot slip a private address past a
//! check that ran before resolution.
//!
//! The allowlist is configuration, so it is read from the same `[[acl]]` table
//! that authorised the access in the first place: a rule that writes the address
//! range down (`host_cidr`) is an explicit allowlist entry, while an ordinary
//! rule that merely says "any address" is not, because it never named the
//! target. Keeping both gates in one table also means the per-caller, per-port,
//! and per-protocol matching rules cannot drift apart from the ACL's own.
//!
//! Nothing here dials. [`EgressPolicy::check`] is a pure predicate over one
//! already-resolved address, which is what makes it unit-testable without a
//! network.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use wsnet_routing::{AclDecision, AclQuery, AclRule, AclTable};

/// The instance-metadata address used by AWS, Azure, GCP, and OpenStack.
const METADATA_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
/// The ECS task-metadata address, which is a second link-local endpoint.
const METADATA_ECS_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 170, 2);

/// The class DESIGN.md section 9.3 sorts an egress target into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressClass {
    /// Globally routable; the only class public egress reaches without an
    /// explicit allowlist entry.
    Public,
    /// `127.0.0.0/8` or `::1`.
    Loopback,
    /// RFC 1918 private space: `10/8`, `172.16/12`, `192.168/16`.
    Private,
    /// `169.254.0.0/16` or `fe80::/10`.
    LinkLocal,
    /// An instance-metadata endpoint such as `169.254.169.254`.
    CloudMetadata,
    /// IPv6 unique-local space, `fc00::/7`.
    UniqueLocal,
    /// The unspecified address, `0.0.0.0` or `::`.
    Unspecified,
    /// The limited broadcast address, `255.255.255.255`.
    Broadcast,
    /// Shared address space, `100.64.0.0/10`, used by carrier-grade NAT.
    Shared,
    /// IPv4 or IPv6 multicast.
    Multicast,
    /// Any other range that is not globally routable.
    Reserved,
}

impl AddressClass {
    /// Whether this class may be reached without an explicit allowlist entry.
    pub const fn is_public(self) -> bool {
        matches!(self, AddressClass::Public)
    }

    /// A short, log-safe name for the class.
    ///
    /// Section 9.1 keeps the reason for a refusal inside the protected record,
    /// so this text is only ever sent to the authenticated peer, never to an
    /// unauthenticated one.
    pub const fn detail(self) -> &'static str {
        match self {
            AddressClass::Public => "a globally routable address",
            AddressClass::Loopback => "a loopback address",
            AddressClass::Private => "a private address",
            AddressClass::LinkLocal => "a link-local address",
            AddressClass::CloudMetadata => "a cloud instance-metadata address",
            AddressClass::UniqueLocal => "an IPv6 unique-local address",
            AddressClass::Unspecified => "the unspecified address",
            AddressClass::Broadcast => "the broadcast address",
            AddressClass::Shared => "a shared (carrier-grade NAT) address",
            AddressClass::Multicast => "a multicast address",
            AddressClass::Reserved => "a reserved address",
        }
    }
}

/// Sorts one address into the class section 9.3 refuses by default.
///
/// Section 9.3 lists loopback, private, link-local, and cloud metadata
/// explicitly and closes the list with "and similar special addresses", so
/// anything that is not globally routable is treated as special: the caller can
/// still reach it, but only through an explicit allowlist entry.
pub fn classify(ip: IpAddr) -> AddressClass {
    match ip {
        IpAddr::V4(ip) => classify_v4(ip),
        IpAddr::V6(ip) => classify_v6(ip),
    }
}

fn classify_v4(ip: Ipv4Addr) -> AddressClass {
    let octets = ip.octets();
    if ip.is_broadcast() {
        return AddressClass::Broadcast;
    }
    if ip.is_loopback() {
        return AddressClass::Loopback;
    }
    if ip.is_private() {
        return AddressClass::Private;
    }
    if ip.is_link_local() {
        return if ip == METADATA_V4 || ip == METADATA_ECS_V4 {
            AddressClass::CloudMetadata
        } else {
            AddressClass::LinkLocal
        };
    }
    // `0.0.0.0/8` is "this network"; only `0.0.0.0` itself is the unspecified
    // address, and the rest of the range is just as unroutable.
    if octets[0] == 0 {
        return AddressClass::Unspecified;
    }
    if ip.is_multicast() {
        return AddressClass::Multicast;
    }
    if v4_in(&[100, 64, 0, 0], 10, ip) {
        return AddressClass::Shared;
    }
    if v4_in(&[192, 0, 0, 0], 24, ip)
        || v4_in(&[192, 0, 2, 0], 24, ip)
        || v4_in(&[192, 88, 99, 0], 24, ip)
        || v4_in(&[198, 18, 0, 0], 15, ip)
        || v4_in(&[198, 51, 100, 0], 24, ip)
        || v4_in(&[203, 0, 113, 0], 24, ip)
        || octets[0] >= 240
    {
        return AddressClass::Reserved;
    }
    AddressClass::Public
}

fn classify_v6(ip: Ipv6Addr) -> AddressClass {
    // An IPv4-mapped address is an IPv4 address; classifying the embedded form
    // is what stops `::ffff:127.0.0.1` from looking globally routable.
    if let Some(embedded) = ip.to_ipv4_mapped() {
        return classify_v4(embedded);
    }
    if ip.is_unspecified() {
        return AddressClass::Unspecified;
    }
    if ip.is_loopback() {
        return AddressClass::Loopback;
    }
    if ip.is_multicast() {
        return AddressClass::Multicast;
    }
    let segments = ip.segments();
    // `fc00::/7` unique-local, which is also where the IPv6 instance-metadata
    // endpoint (`fd00:ec2::254`) of section 9.3 lives.
    if (segments[0] & 0xfe00) == 0xfc00 {
        return AddressClass::UniqueLocal;
    }
    // `fe80::/10`.
    if (segments[0] & 0xffc0) == 0xfe80 {
        return AddressClass::LinkLocal;
    }
    // `64:ff9b::/96` (NAT64) and `2002::/16` (6to4) both carry an IPv4 address,
    // so the embedded form decides and a wrapped private address stays refused.
    if segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0
    {
        return classify_v4(embedded_v4(segments[6], segments[7]));
    }
    if segments[0] == 0x2002 {
        return classify_v4(embedded_v4(segments[1], segments[2]));
    }
    // Teredo, `2001::/32`.
    if segments[0] == 0x2001 && segments[1] == 0 {
        return AddressClass::Reserved;
    }
    // Documentation, `2001:db8::/32`.
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return AddressClass::Reserved;
    }
    // Discard-only, `100::/64`.
    if segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 {
        return AddressClass::Reserved;
    }
    // Deprecated site-local, `fec0::/10`.
    if (segments[0] & 0xffc0) == 0xfec0 {
        return AddressClass::Reserved;
    }
    // `2001:2::/48` benchmarking, `2001:10::/28` ORCHID, `2001:20::/28` ORCHIDv2.
    if segments[0] == 0x2001 && (segments[1] == 0x0002 || (segments[1] & 0xfff0) == 0x0010) {
        return AddressClass::Reserved;
    }
    AddressClass::Public
}

const fn embedded_v4(high: u16, low: u16) -> Ipv4Addr {
    Ipv4Addr::new(
        (high >> 8) as u8,
        (high & 0x00ff) as u8,
        (low >> 8) as u8,
        (low & 0x00ff) as u8,
    )
}

/// Whether `ip` falls inside `net/prefix`.
fn v4_in(net: &[u8; 4], prefix: u8, ip: Ipv4Addr) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    let net = u32::from_be_bytes(*net);
    (u32::from(ip) & mask) == (net & mask)
}

/// Why one resolved address may not be connected to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressRefusal {
    /// The address is a special-purpose class and no explicit allowlist rule
    /// covers it (section 9.3's default refusal).
    Special(AddressClass),
    /// The address is globally routable, but no ACL rule permits this concrete
    /// address. This is the section 9.3 half that a deny rule covering a CIDR
    /// enforces: the name was allowed, the address it resolved to is not.
    NotPermitted,
}

impl EgressRefusal {
    /// A short, log-safe explanation for the authenticated peer.
    pub fn detail(self) -> String {
        match self {
            EgressRefusal::Special(class) => format!(
                "egress refused {}: no explicit allowlist rule permits it",
                class.detail()
            ),
            EgressRefusal::NotPermitted => {
                "egress refused: no acl rule permits this resolved address".to_string()
            }
        }
    }
}

/// The two-gate egress decision of section 9.3.
///
/// Both gates come from the deployment's `[[acl]]` table: the first is the whole
/// table, so that a rule naming a CIDR is honoured for the address a *name*
/// resolved to, and the second is only the rules that name a CIDR, so that an
/// ordinary "any address" rule cannot exempt a local target by accident.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    all: AclTable,
    explicit: AclTable,
}

impl EgressPolicy {
    /// A policy that refuses every special-purpose address.
    pub fn public_only() -> Self {
        EgressPolicy {
            all: AclTable::deny_all(),
            explicit: AclTable::deny_all(),
        }
    }

    /// Derives the policy from the deployment's ACL rules.
    ///
    /// A rule with an invalid CIDR is impossible here: [`crate::Hub::new`] and
    /// [`crate::Hub::with_profiles`] compile the same rules first and fail at
    /// startup. If one appeared anyway, the tables fall back to deny-all, which
    /// refuses rather than widens.
    pub fn from_rules(rules: &[AclRule]) -> Self {
        let explicit: Vec<AclRule> = rules
            .iter()
            .filter(|rule| rule.host_cidr.is_some())
            .cloned()
            .collect();
        EgressPolicy {
            all: AclTable::new(rules.to_vec()).unwrap_or_else(|_| AclTable::deny_all()),
            explicit: AclTable::new(explicit).unwrap_or_else(|_| AclTable::deny_all()),
        }
    }

    /// Decides whether one already-resolved address may be dialled.
    ///
    /// The caller passes the same access the ACL already decided once, with the
    /// concrete address filled in: section 9.3 requires every *actual candidate
    /// IP* to be checked, and a name cannot be checked.
    pub fn check(&self, query: &AclQuery<'_>, ip: IpAddr) -> Result<(), EgressRefusal> {
        let mut concrete = query.clone();
        concrete.ip = Some(ip);
        let class = classify(ip);
        if class.is_public() {
            return if self.all.check(&concrete) == AclDecision::Allowed {
                Ok(())
            } else {
                Err(EgressRefusal::NotPermitted)
            };
        }
        // Section 9.3: a local service is the intended way to reach a local
        // address, so a plain address open needs a rule that wrote the range
        // down. A non-CIDR rule is deliberately not enough.
        if self.explicit.check(&concrete) == AclDecision::Allowed {
            Ok(())
        } else {
            Err(EgressRefusal::Special(class))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wsnet_routing::{AclAction, Proto};

    fn rule(allow: bool, host_cidr: Option<&str>) -> AclRule {
        AclRule {
            caller: "client-a".into(),
            action: AclAction::ConnectAddress,
            allow,
            node: None,
            service: None,
            host_cidr: host_cidr.map(Into::into),
            ports: None,
            proto: None,
        }
    }

    fn query(caller: &str) -> AclQuery<'_> {
        AclQuery {
            caller,
            action: AclAction::ConnectAddress,
            node: None,
            service: None,
            ip: None,
            port: Some(443),
            proto: Proto::Tcp,
        }
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("a literal address")
    }

    #[test]
    fn every_range_section_9_3_lists_is_special() {
        for (text, expected) in [
            ("127.0.0.1", AddressClass::Loopback),
            ("127.255.255.254", AddressClass::Loopback),
            ("::1", AddressClass::Loopback),
            ("10.1.2.3", AddressClass::Private),
            ("172.16.0.1", AddressClass::Private),
            ("172.31.255.255", AddressClass::Private),
            ("192.168.1.1", AddressClass::Private),
            ("169.254.0.1", AddressClass::LinkLocal),
            ("fe80::1", AddressClass::LinkLocal),
            ("169.254.169.254", AddressClass::CloudMetadata),
            ("169.254.170.2", AddressClass::CloudMetadata),
            ("fd00:ec2::254", AddressClass::UniqueLocal),
            ("fd12:3456::1", AddressClass::UniqueLocal),
            ("0.0.0.0", AddressClass::Unspecified),
            ("0.1.2.3", AddressClass::Unspecified),
            ("::", AddressClass::Unspecified),
            ("255.255.255.255", AddressClass::Broadcast),
            ("100.64.0.1", AddressClass::Shared),
            ("224.0.0.1", AddressClass::Multicast),
            ("ff02::1", AddressClass::Multicast),
            ("198.18.0.1", AddressClass::Reserved),
            ("192.0.2.1", AddressClass::Reserved),
            ("240.0.0.1", AddressClass::Reserved),
            ("::ffff:10.0.0.1", AddressClass::Private),
            ("::ffff:127.0.0.1", AddressClass::Loopback),
            ("2002:0a00:0001::1", AddressClass::Private),
            ("64:ff9b::c0a8:0101", AddressClass::Private),
            ("2001:db8::1", AddressClass::Reserved),
        ] {
            assert_eq!(classify(ip(text)), expected, "{text}");
            assert!(!classify(ip(text)).is_public(), "{text}");
        }
        for text in ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111"] {
            assert_eq!(classify(ip(text)), AddressClass::Public, "{text}");
        }
    }

    #[test]
    fn public_egress_is_decided_by_the_acl_alone() {
        let permitted = EgressPolicy::from_rules(&[rule(true, None)]);
        assert_eq!(
            permitted.check(&query("client-a"), ip("93.184.216.34")),
            Ok(())
        );
        assert_eq!(
            permitted.check(&query("client-b"), ip("93.184.216.34")),
            Err(EgressRefusal::NotPermitted)
        );

        let empty = EgressPolicy::public_only();
        assert_eq!(
            empty.check(&query("client-a"), ip("93.184.216.34")),
            Err(EgressRefusal::NotPermitted)
        );
    }

    #[test]
    fn only_a_rule_that_names_the_range_exempts_a_special_address() {
        // A rule that names no range is not an allowlist entry, however broad.
        let broad = EgressPolicy::from_rules(&[rule(true, None)]);
        for text in ["127.0.0.1", "10.0.0.1", "169.254.169.254", "fd00::1"] {
            assert_eq!(
                broad.check(&query("client-a"), ip(text)),
                Err(EgressRefusal::Special(classify(ip(text)))),
                "{text}"
            );
        }

        // Writing the range down is what section 9.3 calls an explicit entry.
        let explicit = EgressPolicy::from_rules(&[rule(true, Some("10.0.0.0/8"))]);
        assert_eq!(explicit.check(&query("client-a"), ip("10.1.2.3")), Ok(()));
        // It is still per caller and per target.
        assert_eq!(
            explicit.check(&query("client-b"), ip("10.1.2.3")),
            Err(EgressRefusal::Special(AddressClass::Private))
        );
        assert_eq!(
            explicit.check(&query("client-a"), ip("192.168.1.1")),
            Err(EgressRefusal::Special(AddressClass::Private))
        );

        // The named local service exception of section 9.3 is a rule that names
        // the loopback or metadata range a local service publishes on.
        let local = EgressPolicy::from_rules(&[rule(true, Some("127.0.0.1/32"))]);
        assert_eq!(local.check(&query("client-a"), ip("127.0.0.1")), Ok(()));
        assert_eq!(
            local.check(&query("client-a"), ip("127.0.0.2")),
            Err(EgressRefusal::Special(AddressClass::Loopback))
        );

        let metadata = EgressPolicy::from_rules(&[rule(true, Some("169.254.169.254/32"))]);
        assert_eq!(
            metadata.check(&query("client-a"), ip("169.254.169.254")),
            Ok(())
        );
    }

    #[test]
    fn a_deny_rule_that_names_a_range_applies_to_the_resolved_address() {
        // The first matching rule wins, exactly as in the ACL itself: a name
        // that resolves into the denied range is refused even though the broad
        // allow rule is what authorised the name.
        let policy = EgressPolicy::from_rules(&[rule(false, Some("1.2.3.0/24")), rule(true, None)]);
        assert_eq!(
            policy.check(&query("client-a"), ip("1.2.3.7")),
            Err(EgressRefusal::NotPermitted)
        );
        assert_eq!(policy.check(&query("client-a"), ip("8.8.8.8")), Ok(()));
    }

    #[test]
    fn a_port_restriction_still_applies_to_the_concrete_address() {
        let mut restricted = rule(true, None);
        restricted.ports = Some(vec![443]);
        let policy = EgressPolicy::from_rules(&[restricted]);

        let mut on_443 = query("client-a");
        on_443.port = Some(443);
        assert_eq!(policy.check(&on_443, ip("93.184.216.34")), Ok(()));

        let mut on_22 = query("client-a");
        on_22.port = Some(22);
        assert_eq!(
            policy.check(&on_22, ip("93.184.216.34")),
            Err(EgressRefusal::NotPermitted)
        );
    }

    #[test]
    fn a_refusal_detail_names_the_class_without_leaking_the_target() {
        let refusal = EgressRefusal::Special(AddressClass::CloudMetadata);
        assert!(refusal.detail().contains("instance-metadata"));
        assert!(EgressRefusal::NotPermitted
            .detail()
            .contains("resolved address"));
        // The detail names a class, never the address that was probed.
        assert!(!refusal.detail().contains("169.254"));
    }
}
