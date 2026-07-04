//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

//! BGP definitions common to `holo-bgp` and `holo-policy`
//!
//! This file contains BGP definitions that are common to both `holo-bgp` and
//! `holo-policy`. In the future, the northbound layer should be restructured
//! so that `holo-bgp` can handle the BGP-specific policy definitions itself,
//! eliminating the need for shared definitions.

use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr};

use holo_yang::{ToYang, TryFromYang};
use itertools::Itertools;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use regex::Regex;
use serde::{Deserialize, Serialize};

// Configurable (AFI,SAFI) tuples.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum AfiSafi {
    Ipv4Unicast,
    Ipv6Unicast,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum RouteType {
    Internal,
    External,
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum Origin {
    Igp = 0,
    Egp = 1,
    #[default]
    Incomplete = 2,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct Comm(pub u32);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct ExtComm(pub [u8; 8]);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct Extv6Comm(pub Ipv6Addr, pub u32);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct LargeComm(pub [u8; 12]);

// BGP Well-known Communities.
//
// IANA registry:
// https://www.iana.org/assignments/bgp-well-known-communities/bgp-well-known-communities.xhtml
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
#[repr(u32)]
pub enum WellKnownCommunities {
    NoExport = 0xFFFFFF01,
    NoAdvertise = 0xFFFFFF02,
    NoExportSubconfed = 0xFFFFFF03,
}

// ===== impl AfiSafi =====

impl ToYang for AfiSafi {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            AfiSafi::Ipv4Unicast => "iana-bgp-types:ipv4-unicast".into(),
            AfiSafi::Ipv6Unicast => "iana-bgp-types:ipv6-unicast".into(),
        }
    }
}

impl TryFromYang for AfiSafi {
    fn try_from_yang(value: &str) -> Option<AfiSafi> {
        match value {
            "iana-bgp-types:ipv4-unicast" => Some(AfiSafi::Ipv4Unicast),
            "iana-bgp-types:ipv6-unicast" => Some(AfiSafi::Ipv6Unicast),
            _ => None,
        }
    }
}

// ===== impl RouteType =====

impl TryFromYang for RouteType {
    fn try_from_yang(value: &str) -> Option<RouteType> {
        match value {
            "internal" => Some(RouteType::Internal),
            "external" => Some(RouteType::External),
            _ => None,
        }
    }
}

// ===== impl Origin =====

impl ToYang for Origin {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            Origin::Igp => "igp".into(),
            Origin::Egp => "egp".into(),
            Origin::Incomplete => "incomplete".into(),
        }
    }
}

impl TryFromYang for Origin {
    fn try_from_yang(value: &str) -> Option<Origin> {
        match value {
            "igp" => Some(Origin::Igp),
            "egp" => Some(Origin::Egp),
            "incomplete" => Some(Origin::Incomplete),
            _ => None,
        }
    }
}

// ===== impl WellKnownCommunities =====

impl ToYang for WellKnownCommunities {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            WellKnownCommunities::NoExport => {
                "iana-bgp-community-types:no-export".into()
            }
            WellKnownCommunities::NoAdvertise => {
                "iana-bgp-community-types:no-advertise".into()
            }
            WellKnownCommunities::NoExportSubconfed => {
                "iana-bgp-community-types:no-export-subconfed".into()
            }
        }
    }
}

impl TryFromYang for WellKnownCommunities {
    fn try_from_yang(value: &str) -> Option<WellKnownCommunities> {
        match value {
            "iana-bgp-community-types:no-export" => {
                Some(WellKnownCommunities::NoExport)
            }
            "iana-bgp-community-types:no-advertise" => {
                Some(WellKnownCommunities::NoAdvertise)
            }
            "iana-bgp-community-types:no-export-subconfed" => {
                Some(WellKnownCommunities::NoExportSubconfed)
            }
            _ => None,
        }
    }
}

// ===== impl Comm =====

impl ToYang for Comm {
    fn to_yang(&self) -> Cow<'static, str> {
        match WellKnownCommunities::from_u32(self.0) {
            Some(comm) => {
                // Return well-known community identity.
                comm.to_yang()
            }
            None => {
                // Return community as plain integer.
                let global = self.0 >> 16;
                let local = self.0 & 0xFFFF;
                format!("{global}:{local}").into()
            }
        }
    }
}

impl TryFromYang for Comm {
    fn try_from_yang(value: &str) -> Option<Comm> {
        // Parse well-known community identity.
        if let Some(comm) = WellKnownCommunities::try_from_yang(value) {
            return Some(Comm(comm as u32));
        }

        // Parse plain integer community.
        if let Ok(comm) = value.parse::<u32>() {
            return Some(Comm(comm));
        }

        // Parse community in the "global:local" format.
        let re = Regex::new(r"^([0-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-5][0-9]{3}|66[0-4][0-9]{2}|665[0-2][0-9]|6653[0-5]):([0-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-5][0-9]{3}|66[0-4][0-9]{2}|665[0-2][0-9]|6653[0-5])$").unwrap();
        if let Some(captures) = re.captures(value) {
            let global =
                captures.get(1).unwrap().as_str().parse::<u32>().unwrap();
            let local =
                captures.get(2).unwrap().as_str().parse::<u32>().unwrap();
            let comm = (global << 16) | local;
            return Some(Comm(comm));
        }

        None
    }
}

// ===== impl ExtComm =====

impl ToYang for ExtComm {
    fn to_yang(&self) -> Cow<'static, str> {
        // TODO: cover other cases instead of always using the raw format.
        format!(
            "raw:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0],
            self.0[1],
            self.0[2],
            self.0[3],
            self.0[4],
            self.0[5],
            self.0[6],
            self.0[7]
        )
        .into()
    }
}

impl TryFromYang for ExtComm {
    fn try_from_yang(value: &str) -> Option<ExtComm> {
        // Parse extended community in the raw format.
        if let Some(bytes) = value.strip_prefix("raw:") {
            let bytes = bytes
                .split(':')
                .map(|byte| u8::from_str_radix(byte, 16).ok())
                .collect::<Option<Vec<_>>>()?;
            return Some(ExtComm(bytes.try_into().ok()?));
        }

        // Parse Route-Target and Route-Origin extended communities.
        let (kind, value) = value.split_once(':')?;
        let subtype = match kind {
            "route-target" => 0x02,
            "route-origin" => 0x03,
            _ => return None,
        };
        let mut comm = [0u8; 8];
        comm[1] = subtype;
        if let Some((global, local)) = value.split_once(':') {
            if let Ok(addr) = global.parse::<Ipv4Addr>() {
                // IPv4 address specific.
                comm[0] = 0x01;
                comm[2..6].copy_from_slice(&addr.octets());
                comm[6..]
                    .copy_from_slice(&local.parse::<u16>().ok()?.to_be_bytes());
            } else {
                let asn = global.parse::<u32>().ok()?;
                if let Ok(asn) = u16::try_from(asn) {
                    // Two-octet AS specific.
                    comm[2..4].copy_from_slice(&asn.to_be_bytes());
                    comm[4..].copy_from_slice(
                        &local.parse::<u32>().ok()?.to_be_bytes(),
                    );
                } else {
                    // Four-octet AS specific.
                    comm[0] = 0x02;
                    comm[2..6].copy_from_slice(&asn.to_be_bytes());
                    comm[6..].copy_from_slice(
                        &local.parse::<u16>().ok()?.to_be_bytes(),
                    );
                }
            }
        } else {
            // Four-octet AS specific. The YANG pattern concatenates the AS
            // number and the local administrator without a separator, so
            // split greedily, preferring the longest possible AS number.
            let (asn, local) = (1..value.len()).rev().find_map(|pos| {
                let (asn, local) = value.split_at(pos);
                let asn = asn.parse::<u32>().ok()?;
                let local = local.parse::<u16>().ok()?;
                Some((asn, local))
            })?;
            comm[0] = 0x02;
            comm[2..6].copy_from_slice(&asn.to_be_bytes());
            comm[6..].copy_from_slice(&local.to_be_bytes());
        }
        Some(ExtComm(comm))
    }
}

// ===== impl Extv6Comm =====

impl ToYang for Extv6Comm {
    fn to_yang(&self) -> Cow<'static, str> {
        // TODO: cover other cases instead of always using the raw format.
        let bytes = self
            .0
            .octets()
            .into_iter()
            .chain(self.1.to_be_bytes())
            .map(|byte| format!("{byte:02x}"))
            .join(":");
        format!("ipv6-raw:{bytes}").into()
    }
}

impl TryFromYang for Extv6Comm {
    fn try_from_yang(value: &str) -> Option<Extv6Comm> {
        // Parse IPv6 extended community in the raw format (20 colon
        // separated byte groups).
        if let Some(value) = value.strip_prefix("ipv6-raw:") {
            let bytes = value
                .split(':')
                .map(|byte| u8::from_str_radix(byte, 16).ok())
                .collect::<Option<Vec<_>>>()?;
            let (addr, local) = bytes.split_at(bytes.len().checked_sub(4)?);
            let addr = Ipv6Addr::from(<[u8; 16]>::try_from(addr).ok()?);
            let local = u32::from_be_bytes(local.try_into().ok()?);
            return Some(Extv6Comm(addr, local));
        }

        // Parse IPv6 Route-Target and Route-Origin extended communities.
        let (kind, value) = value.split_once(':')?;
        let subtype: u8 = match kind {
            "ipv6-route-target" => 0x02,
            "ipv6-route-origin" => 0x03,
            _ => return None,
        };
        let (addr, local) = value.rsplit_once(':')?;
        let addr = addr.parse::<Ipv6Addr>().ok()?;
        let local = local.parse::<u16>().ok()?;
        // Pack the wire layout (type, subtype, global administrator and
        // local administrator octets) into the same 16+4 byte split used
        // by the wire codec.
        let mut bytes = [0u8; 20];
        bytes[1] = subtype;
        bytes[2..18].copy_from_slice(&addr.octets());
        bytes[18..].copy_from_slice(&local.to_be_bytes());
        let addr = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[..16]).ok()?);
        let local = u32::from_be_bytes(bytes[16..].try_into().ok()?);
        Some(Extv6Comm(addr, local))
    }
}

// ===== impl LargeComm =====

impl ToYang for LargeComm {
    fn to_yang(&self) -> Cow<'static, str> {
        format!(
            "{}:{}:{}",
            u32::from_be_bytes(self.0[0..4].try_into().unwrap()),
            u32::from_be_bytes(self.0[4..8].try_into().unwrap()),
            u32::from_be_bytes(self.0[8..12].try_into().unwrap()),
        )
        .into()
    }
}

impl TryFromYang for LargeComm {
    fn try_from_yang(value: &str) -> Option<LargeComm> {
        // Parse large community in the "global:local:local" format.
        let mut parts = value.split(':');
        let global = parts.next()?.parse::<u32>().ok()?;
        let local1 = parts.next()?.parse::<u32>().ok()?;
        let local2 = parts.next()?.parse::<u32>().ok()?;
        if parts.next().is_some() {
            return None;
        }

        let mut comm = [0u8; 12];
        comm[..4].copy_from_slice(&global.to_be_bytes());
        comm[4..8].copy_from_slice(&local1.to_be_bytes());
        comm[8..].copy_from_slice(&local2.to_be_bytes());
        Some(LargeComm(comm))
    }
}
