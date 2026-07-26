//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use holo_utils::bgp::AfiSafi;
use holo_utils::ip::{IpAddrKind, IpNetworkKind};
use ipnetwork::{Ipv4Network, Ipv6Network};
use prefix_trie::Prefix;

use crate::error::Error;
use crate::neighbor::{
    Neighbor, NeighborUpdateQueue, NeighborUpdateQueues, PeerType,
};
use crate::packet::attribute::{self, ATTR_MIN_LEN_EXT, BaseAttrs};
use crate::packet::iana::{Afi, Safi};
use crate::packet::message::{
    Message, MpReachNlri, MpUnreachNlri, ReachNlri, UnreachNlri, UpdateMsg,
};
use crate::rib::{RoutingTable, RoutingTables};

// BGP address-family specific code.
pub trait AddressFamily: Sized {
    // Address Family Identifier.
    const AFI: Afi;
    // Subsequent Address Family Identifier.
    const SAFI: Safi;
    // Combined AFI and SAFI.
    const AFI_SAFI: AfiSafi;

    // The type of IP address used by this address family.
    type IpAddr: IpAddrKind;
    // The type of IP network used by this address family.
    type IpNetwork: IpNetworkKind<Self::IpAddr> + prefix_trie::Prefix;

    // Get the routing table for this address family from the provided
    // `RoutingTables`.
    fn table(tables: &mut RoutingTables) -> &mut RoutingTable<Self>;

    // Get the update queue for this address family from the provided
    // `NeighborUpdateQueues`.
    fn update_queue(
        queues: &mut NeighborUpdateQueues,
    ) -> &mut NeighborUpdateQueue<Self>;

    // Extract the next hop IP address from the received BGP attributes.
    fn nexthop_rx_extract(attrs: &BaseAttrs) -> IpAddr;

    // Modify the next hop(s) for transmission.
    fn nexthop_tx_change(
        nbr: &Neighbor,
        nexthop_self: bool,
        attrs: &mut BaseAttrs,
    );

    // Build BGP UPDATE messages based on the provided update queue.
    fn build_updates(queue: &mut NeighborUpdateQueue<Self>) -> Vec<Message>;
}

#[derive(Debug)]
pub struct Ipv4Unicast;

#[derive(Debug)]
pub struct Ipv6Unicast;

// ===== impl Ipv4Unicast =====

impl AddressFamily for Ipv4Unicast {
    const AFI: Afi = Afi::Ipv4;
    const SAFI: Safi = Safi::Unicast;
    const AFI_SAFI: AfiSafi = AfiSafi::Ipv4Unicast;

    type IpAddr = Ipv4Addr;
    type IpNetwork = Ipv4Network;

    fn table(tables: &mut RoutingTables) -> &mut RoutingTable<Self> {
        &mut tables.ipv4_unicast
    }

    fn update_queue(
        queues: &mut NeighborUpdateQueues,
    ) -> &mut NeighborUpdateQueue<Self> {
        &mut queues.ipv4_unicast
    }

    fn nexthop_rx_extract(attrs: &BaseAttrs) -> IpAddr {
        attrs.nexthop.unwrap()
    }

    fn nexthop_tx_change(
        nbr: &Neighbor,
        nexthop_self: bool,
        attrs: &mut BaseAttrs,
    ) {
        // Get source address of the BGP session.
        let session_src = match nbr.conn_info.as_ref().unwrap().local_addr {
            IpAddr::V4(addr) => {
                // BGP over IPv4.
                addr
            }
            IpAddr::V6(_addr) => {
                // BGP over IPv6.
                //
                // TODO: use IPv4 address of the corresponding system interface.
                Ipv4Addr::UNSPECIFIED
            }
        };

        // Use the source address of the session as next hop.
        if nexthop_self {
            attrs.nexthop = Some(session_src.into());
            return;
        }

        match nbr.peer_type {
            PeerType::Internal => {
                // Next hop isn't modified.
            }
            PeerType::External => {
                if !nbr.shared_subnet {
                    // Update next hop using the source address of the eBGP
                    // session.
                    attrs.nexthop = Some(session_src.into());
                } else {
                    // Next hop isn't modified (eBGP next hop optimization).
                }
            }
        }
    }

    fn build_updates(queue: &mut NeighborUpdateQueue<Self>) -> Vec<Message> {
        let mut msgs = vec![];
        let reach = std::mem::take(&mut queue.reach);
        let unreach = std::mem::take(&mut queue.unreach);

        // Reachable prefixes.
        for (attrs, prefixes) in reach.into_iter() {
            let nexthop = Ipv4Addr::get(attrs.base.nexthop.unwrap()).unwrap();
            let attrs_len = attrs.length() + attribute::nexthop::length();
            let Some(chunks) = nlri_chunks(prefixes, attrs_len) else {
                Error::UpdateAttrsTooLong(attrs_len).log();
                continue;
            };

            msgs.extend(chunks.map(|prefixes| {
                let reach = ReachNlri { prefixes, nexthop };
                Message::Update(UpdateMsg {
                    reach: Some(reach),
                    unreach: None,
                    mp_reach: None,
                    mp_unreach: None,
                    attrs: Some(attrs.clone()),
                })
            }));
        }

        // Unreachable prefixes.
        if !unreach.is_empty()
            && let Some(chunks) = nlri_chunks(unreach, 0)
        {
            msgs.extend(chunks.map(|prefixes| {
                let unreach = UnreachNlri { prefixes };
                Message::Update(UpdateMsg {
                    reach: None,
                    unreach: Some(unreach),
                    mp_reach: None,
                    mp_unreach: None,
                    attrs: None,
                })
            }));
        }

        msgs
    }
}

// ===== impl Ipv6Unicast =====

impl AddressFamily for Ipv6Unicast {
    const AFI: Afi = Afi::Ipv6;
    const SAFI: Safi = Safi::Unicast;
    const AFI_SAFI: AfiSafi = AfiSafi::Ipv6Unicast;

    type IpAddr = Ipv6Addr;
    type IpNetwork = Ipv6Network;

    fn table(tables: &mut RoutingTables) -> &mut RoutingTable<Self> {
        &mut tables.ipv6_unicast
    }

    fn update_queue(
        queues: &mut NeighborUpdateQueues,
    ) -> &mut NeighborUpdateQueue<Self> {
        &mut queues.ipv6_unicast
    }

    fn nexthop_rx_extract(attrs: &BaseAttrs) -> IpAddr {
        attrs
            .ll_nexthop
            .map(IpAddr::from)
            .unwrap_or(attrs.nexthop.unwrap())
    }

    fn nexthop_tx_change(
        nbr: &Neighbor,
        nexthop_self: bool,
        attrs: &mut BaseAttrs,
    ) {
        // Get source address of the BGP session.
        let session_src = match nbr.conn_info.as_ref().unwrap().local_addr {
            IpAddr::V4(addr) => {
                // BGP over IPv4 (IPv4-mapped IPv6 address).
                addr.to_ipv6_mapped()
            }
            IpAddr::V6(addr) => {
                // BGP over IPv6.
                addr
            }
        };

        // Use the source address of the session as next hop.
        if nexthop_self {
            attrs.nexthop = Some(session_src.into());
            if nbr.shared_subnet {
                // TODO: update link-local next hop.
            }
            return;
        }

        match nbr.peer_type {
            PeerType::Internal => {
                // Global next hop isn't modified.

                // TODO: update link-local next hop.
            }
            PeerType::External => {
                if !nbr.shared_subnet {
                    // Update global next hop using the source address of the
                    // eBGP session.
                    attrs.nexthop = Some(session_src.into());

                    // Unset link-local next hop.
                    attrs.ll_nexthop = None;
                } else {
                    // Global next hop isn't modified (eBGP next hop
                    // optimization).

                    // TODO: update link-local next hop.
                }
            }
        }
    }

    fn build_updates(queue: &mut NeighborUpdateQueue<Self>) -> Vec<Message> {
        let mut msgs = vec![];
        let reach = std::mem::take(&mut queue.reach);
        let unreach = std::mem::take(&mut queue.unreach);

        // Reachable prefixes.
        for (attrs, prefixes) in reach.into_iter() {
            let nexthop = Ipv6Addr::get(attrs.base.nexthop.unwrap()).unwrap();
            let ll_nexthop = attrs.base.ll_nexthop;
            let nexthop_len = if ll_nexthop.is_some() { 32 } else { 16 };
            let attrs_len = attrs.length()
                + ATTR_MIN_LEN_EXT
                + MpReachNlri::MIN_LEN
                + nexthop_len;
            let Some(chunks) = nlri_chunks(prefixes, attrs_len) else {
                Error::UpdateAttrsTooLong(attrs_len).log();
                continue;
            };

            msgs.extend(chunks.map(|prefixes| {
                let mp_reach = MpReachNlri::Ipv6Unicast {
                    prefixes,
                    nexthop,
                    ll_nexthop,
                };
                Message::Update(UpdateMsg {
                    reach: None,
                    unreach: None,
                    mp_reach: Some(mp_reach),
                    mp_unreach: None,
                    attrs: Some(attrs.clone()),
                })
            }));
        }

        // Unreachable prefixes.
        if !unreach.is_empty()
            && let Some(chunks) =
                nlri_chunks(unreach, ATTR_MIN_LEN_EXT + MpUnreachNlri::MIN_LEN)
        {
            msgs.extend(chunks.map(|prefixes| {
                let mp_unreach = MpUnreachNlri::Ipv6Unicast { prefixes };
                Message::Update(UpdateMsg {
                    reach: None,
                    unreach: None,
                    mp_reach: None,
                    mp_unreach: Some(mp_unreach),
                    attrs: None,
                })
            }));
        }

        msgs
    }
}

// ===== helper functions =====

// Number of bytes occupied by a prefix encoded as NLRI: one octet for the
// prefix length, followed by the significant bytes of the prefix address.
fn nlri_len<P: Prefix>(prefix: &P) -> u16 {
    1 + u16::from(prefix.prefix_len()).div_ceil(8)
}

// Groups the given prefixes into batches that fill an UPDATE message as much
// as possible, where `attr_len` is the number of bytes occupied by the path
// attributes, excluding any NLRI they carry.
//
// Returns `None` when the attributes leave no room for a prefix of maximum
// length, in which case the prefixes can't be advertised at all.
fn nlri_chunks<P: Prefix>(
    prefixes: impl IntoIterator<Item = P>,
    attr_len: u16,
) -> Option<impl Iterator<Item = Vec<P>>> {
    // Requiring room for a prefix of maximum length ensures that every batch
    // holds at least one prefix, and hence that the iterator below always
    // makes progress.
    let size = (Message::MAX_LEN - UpdateMsg::MIN_LEN).checked_sub(attr_len)?;
    if size < 1 + (P::num_bits().div_ceil(8) as u16) {
        return None;
    }

    let mut prefixes = prefixes.into_iter().peekable();
    Some(std::iter::from_fn(move || {
        let mut available = size;
        let mut chunk = vec![];
        while let Some(prefix) =
            prefixes.next_if(|prefix| nlri_len(prefix) <= available)
        {
            available -= nlri_len(&prefix);
            chunk.push(prefix);
        }
        (!chunk.is_empty()).then_some(chunk)
    }))
}
