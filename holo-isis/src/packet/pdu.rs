//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::cell::{RefCell, RefMut};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use holo_utils::bytes::TLS_BUF;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::packet::consts::{
    LspFlags, PduType, TlvType, IDRP_DISCRIMINATOR, SYSTEM_ID_LEN, VERSION,
    VERSION_PROTO_EXT,
};
use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::tlv::{
    tlv_entries_split, tlv_take_max, AreaAddressesTlv, ExtIpv4Reach,
    ExtIpv4ReachTlv, ExtIsReach, ExtIsReachTlv, Ipv4AddressesTlv, Ipv4Reach,
    Ipv4ReachTlv, Ipv6AddressesTlv, Ipv6Reach, Ipv6ReachTlv, IsReach,
    IsReachTlv, LspBufferSizeTlv, LspEntriesTlv, LspEntry, NeighborsTlv,
    PaddingTlv, ProtocolsSupportedTlv, Tlv, UnknownTlv, TLV_HDR_SIZE,
};
use crate::packet::{AreaAddr, LanId, LevelNumber, LevelType, LspId, SystemId};

// IS-IS PDU.
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum Pdu {
    Hello(Hello),
    Lsp(Lsp),
    Snp(Snp),
}

// IS-IS PDU common header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Header {
    pub pdu_type: PduType,
    pub max_area_addrs: u8,
}

// IS-IS Hello PDU.
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Hello {
    pub hdr: Header,
    pub circuit_type: LevelType,
    pub source: SystemId,
    pub holdtime: u16,
    pub variant: HelloVariant,
    pub tlvs: HelloTlvs,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum HelloVariant {
    Lan { priority: u8, lan_id: LanId },
    P2P { local_circuit_id: u8 },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct HelloTlvs {
    pub protocols_supported: Option<ProtocolsSupportedTlv>,
    pub area_addrs: Vec<AreaAddressesTlv>,
    pub neighbors: Vec<NeighborsTlv>,
    pub ipv4_addrs: Vec<Ipv4AddressesTlv>,
    pub ipv6_addrs: Vec<Ipv6AddressesTlv>,
    pub padding: Vec<PaddingTlv>,
    pub unknown: Vec<UnknownTlv>,
}

// IS-IS Link State PDU.
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Lsp {
    pub hdr: Header,
    pub rem_lifetime: u16,
    pub lsp_id: LspId,
    pub seqno: u32,
    pub cksum: u16,
    pub flags: LspFlags,
    pub tlvs: LspTlvs,
    #[cfg_attr(feature = "testing", serde(default, skip_serializing))]
    pub raw: Bytes,
    // Time the LSP was created or received. When combined with the Remaining
    // Lifetime field, the actual LSP remaining lifetime can be determined.
    #[serde(skip)]
    pub base_time: Option<Instant>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LspTlvs {
    pub protocols_supported: Option<ProtocolsSupportedTlv>,
    pub area_addrs: Vec<AreaAddressesTlv>,
    pub lsp_buf_size: Option<LspBufferSizeTlv>,
    pub is_reach: Vec<IsReachTlv>,
    pub ext_is_reach: Vec<ExtIsReachTlv>,
    pub ipv4_addrs: Vec<Ipv4AddressesTlv>,
    pub ipv4_internal_reach: Vec<Ipv4ReachTlv>,
    pub ipv4_external_reach: Vec<Ipv4ReachTlv>,
    pub ext_ipv4_reach: Vec<ExtIpv4ReachTlv>,
    pub ipv6_addrs: Vec<Ipv6AddressesTlv>,
    pub ipv6_reach: Vec<Ipv6ReachTlv>,
    pub unknown: Vec<UnknownTlv>,
}

// IS-IS Sequence Numbers PDU.
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Snp {
    pub hdr: Header,
    pub source: LanId,
    pub summary: Option<(LspId, LspId)>,
    pub tlvs: SnpTlvs,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct SnpTlvs {
    pub lsp_entries: Vec<LspEntriesTlv>,
    pub unknown: Vec<UnknownTlv>,
}

// ===== impl Pdu =====

impl Pdu {
    // Decodes IS-IS PDU from a bytes buffer.
    pub fn decode(mut buf: Bytes) -> DecodeResult<Self> {
        let packet_len = buf.len();

        // Decode PDU common header.
        let hdr = Header::decode(&mut buf)?;

        // Decode PDU-specific fields.
        let pdu = match hdr.pdu_type {
            PduType::HelloLanL1 | PduType::HelloLanL2 | PduType::HelloP2P => {
                Pdu::Hello(Hello::decode(hdr, packet_len, &mut buf)?)
            }
            PduType::LspL1 | PduType::LspL2 => {
                Pdu::Lsp(Lsp::decode(hdr, packet_len, &mut buf)?)
            }
            PduType::CsnpL1
            | PduType::CsnpL2
            | PduType::PsnpL1
            | PduType::PsnpL2 => {
                Pdu::Snp(Snp::decode(hdr, packet_len, &mut buf)?)
            }
        };

        Ok(pdu)
    }

    // Encodes IS-IS PDU into a bytes buffer.
    pub fn encode(&self) -> Bytes {
        match self {
            Pdu::Hello(pdu) => pdu.encode(),
            Pdu::Lsp(pdu) => pdu.raw.clone(),
            Pdu::Snp(pdu) => pdu.encode(),
        }
    }

    // Returns the IS-IS PDU type.
    pub const fn pdu_type(&self) -> PduType {
        match self {
            Pdu::Hello(pdu) => pdu.hdr.pdu_type,
            Pdu::Lsp(pdu) => pdu.hdr.pdu_type,
            Pdu::Snp(pdu) => pdu.hdr.pdu_type,
        }
    }
}

// ===== impl Header =====

impl Header {
    const LEN: u8 = 8;

    pub const fn new(pdu_type: PduType) -> Self {
        Header {
            pdu_type,
            max_area_addrs: 0,
        }
    }

    // Decodes IS-IS PDU header from a bytes buffer.
    pub fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        let packet_len = buf.len();

        // Ensure the packet has enough data for the fixed-length IS-IS header.
        if packet_len < Self::LEN as _ {
            return Err(DecodeError::IncompletePdu);
        }

        // Parse IDRP discriminator.
        let idrp_discr = buf.get_u8();
        if idrp_discr != IDRP_DISCRIMINATOR {
            return Err(DecodeError::InvalidIrdpDiscriminator(idrp_discr));
        }

        // Parse length of fixed header.
        let fixed_header_length = buf.get_u8();

        // Parse version/protocol ID extension.
        let version_proto_ext = buf.get_u8();
        if version_proto_ext != VERSION_PROTO_EXT {
            return Err(DecodeError::InvalidVersion(version_proto_ext));
        }

        // Parse ID length.
        let id_len = buf.get_u8();
        if id_len != 0 && id_len != SYSTEM_ID_LEN {
            return Err(DecodeError::InvalidIdLength(id_len));
        }

        // Parse PDU type.
        let pdu_type = buf.get_u8();
        let pdu_type = match PduType::from_u8(pdu_type) {
            Some(pdu_type) => pdu_type,
            None => return Err(DecodeError::UnknownPduType(pdu_type)),
        };

        // Additional sanity checks.
        if fixed_header_length != Self::fixed_header_length(pdu_type) {
            return Err(DecodeError::InvalidHeaderLength(fixed_header_length));
        }
        if packet_len < fixed_header_length as _ {
            return Err(DecodeError::IncompletePdu);
        }

        // Parse version.
        let version = buf.get_u8();
        if version != VERSION {
            return Err(DecodeError::InvalidVersion(version));
        }

        // Parse reserved field.
        let _reserved = buf.get_u8();

        // Parse maximum area addresses.
        let max_area_addrs = buf.get_u8();

        Ok(Header {
            pdu_type,
            max_area_addrs,
        })
    }

    // Encodes IS-IS PDU header into a bytes buffer.
    fn encode(&self, buf: &mut BytesMut) {
        // Encode IDRP discriminator.
        buf.put_u8(IDRP_DISCRIMINATOR);
        // Encode length of fixed header.
        buf.put_u8(Self::fixed_header_length(self.pdu_type));
        // Encode version/protocol ID extension.
        buf.put_u8(VERSION_PROTO_EXT);
        // Encode ID length (use default value).
        buf.put_u8(0);
        // Encode PDU type.
        buf.put_u8(self.pdu_type as u8);
        // Encode version.
        buf.put_u8(VERSION);
        // Encode reserved field.
        buf.put_u8(0);
        // Encode maximum area addresses.
        buf.put_u8(self.max_area_addrs);
    }

    // Returns the length of the fixed header for a given PDU type.
    const fn fixed_header_length(pdu_type: PduType) -> u8 {
        match pdu_type {
            PduType::HelloLanL1 | PduType::HelloLanL2 => Hello::HEADER_LEN_LAN,
            PduType::HelloP2P => Hello::HEADER_LEN_P2P,
            PduType::LspL1 | PduType::LspL2 => Lsp::HEADER_LEN,
            PduType::CsnpL1 | PduType::CsnpL2 => Snp::CSNP_HEADER_LEN,
            PduType::PsnpL1 | PduType::PsnpL2 => Snp::PSNP_HEADER_LEN,
        }
    }
}

// ===== impl Hello =====

impl Hello {
    const HEADER_LEN_LAN: u8 = 27;
    const HEADER_LEN_P2P: u8 = 20;
    const CIRCUIT_TYPE_MASK: u8 = 0x03;
    const PRIORITY_MASK: u8 = 0x7F;

    pub fn new(
        level_type: LevelType,
        circuit_type: LevelType,
        source: SystemId,
        holdtime: u16,
        variant: HelloVariant,
        tlvs: HelloTlvs,
    ) -> Self {
        let pdu_type = match level_type {
            LevelType::L1 => PduType::HelloLanL1,
            LevelType::L2 => PduType::HelloLanL2,
            LevelType::All => PduType::HelloP2P,
        };
        Hello {
            hdr: Header::new(pdu_type),
            circuit_type,
            source,
            holdtime,
            variant,
            tlvs,
        }
    }

    fn decode(
        hdr: Header,
        packet_len: usize,
        buf: &mut Bytes,
    ) -> DecodeResult<Self> {
        // Parse circuit type.
        let circuit_type = buf.get_u8() & Self::CIRCUIT_TYPE_MASK;
        let circuit_type = match circuit_type {
            1 if hdr.pdu_type != PduType::HelloLanL2 => LevelType::L1,
            2 if hdr.pdu_type != PduType::HelloLanL1 => LevelType::L2,
            3 => LevelType::All,
            _ => {
                return Err(DecodeError::InvalidHelloCircuitType(circuit_type));
            }
        };

        // Parse source ID.
        let source = SystemId::decode(buf);

        // Parse holding time.
        let holdtime = buf.get_u16();
        if holdtime == 0 {
            return Err(DecodeError::InvalidHelloHoldtime(holdtime));
        }

        // Parse PDU length.
        let pdu_len = buf.get_u16();
        if pdu_len != packet_len as u16 {
            return Err(DecodeError::InvalidPduLength(pdu_len));
        }

        // Parse custom fields.
        let variant = if hdr.pdu_type == PduType::HelloP2P {
            // Parse local circuit ID.
            let local_circuit_id = buf.get_u8();

            HelloVariant::P2P { local_circuit_id }
        } else {
            // Parse priority.
            let priority = buf.get_u8() & Self::PRIORITY_MASK;
            // Parse LAN ID.
            let lan_id = LanId::decode(buf);

            HelloVariant::Lan { priority, lan_id }
        };

        // Parse top-level TLVs.
        let mut tlvs = HelloTlvs::default();
        while buf.remaining() >= TLV_HDR_SIZE {
            // Parse TLV type.
            let tlv_type = buf.get_u8();
            let tlv_etype = TlvType::from_u8(tlv_type);

            // Parse and validate TLV length.
            let tlv_len = buf.get_u8();
            if tlv_len as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            // Parse TLV value.
            let mut buf_tlv = buf.copy_to_bytes(tlv_len as usize);
            match tlv_etype {
                Some(TlvType::AreaAddresses) => {
                    let tlv = AreaAddressesTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.area_addrs.push(tlv);
                }
                Some(TlvType::Neighbors)
                    if hdr.pdu_type != PduType::HelloP2P =>
                {
                    let tlv = NeighborsTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.neighbors.push(tlv);
                }
                Some(TlvType::Padding) => {
                    let tlv = PaddingTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.padding.push(tlv);
                }
                Some(TlvType::ProtocolsSupported) => {
                    if tlvs.protocols_supported.is_some() {
                        continue;
                    }
                    let tlv =
                        ProtocolsSupportedTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.protocols_supported = Some(tlv);
                }
                Some(TlvType::Ipv4Addresses) => {
                    let tlv = Ipv4AddressesTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.ipv4_addrs.push(tlv);
                }
                Some(TlvType::Ipv6Addresses) => {
                    let tlv = Ipv6AddressesTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.ipv6_addrs.push(tlv);
                }
                _ => {
                    // Save unknown top-level TLV.
                    let value = buf_tlv.copy_to_bytes(tlv_len as usize);
                    tlvs.unknown
                        .push(UnknownTlv::new(tlv_type, tlv_len, value));
                }
            }
        }

        Ok(Hello {
            hdr,
            circuit_type,
            source,
            holdtime,
            variant,
            tlvs,
        })
    }

    fn encode(&self) -> Bytes {
        TLS_BUF.with(|buf| {
            let mut buf = pdu_encode_start(buf, &self.hdr);

            let circuit_type = match self.circuit_type {
                LevelType::L1 => 1,
                LevelType::L2 => 2,
                LevelType::All => 3,
            };
            buf.put_u8(circuit_type);
            self.source.encode(&mut buf);
            buf.put_u16(self.holdtime);

            // The PDU length will be initialized later.
            let len_pos = buf.len();
            buf.put_u16(0);

            match self.variant {
                HelloVariant::Lan { priority, lan_id } => {
                    buf.put_u8(priority);
                    lan_id.encode(&mut buf);
                }
                HelloVariant::P2P { local_circuit_id } => {
                    buf.put_u8(local_circuit_id);
                }
            }

            // Encode TLVs.
            if let Some(tlv) = &self.tlvs.protocols_supported {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.area_addrs {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.neighbors {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.ipv4_addrs {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.ipv6_addrs {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.padding {
                tlv.encode(&mut buf);
            }

            pdu_encode_end(buf, len_pos)
        })
    }
}

impl HelloTlvs {
    pub(crate) fn new(
        protocols_supported: impl IntoIterator<Item = u8>,
        area_addrs: impl IntoIterator<Item = AreaAddr>,
        neighbors: impl IntoIterator<Item = [u8; 6]>,
        ipv4_addrs: impl IntoIterator<Item = Ipv4Addr>,
        ipv6_addrs: impl IntoIterator<Item = Ipv6Addr>,
    ) -> Self {
        HelloTlvs {
            protocols_supported: Some(ProtocolsSupportedTlv::from(
                protocols_supported,
            )),
            area_addrs: tlv_entries_split(area_addrs),
            neighbors: tlv_entries_split(neighbors),
            ipv4_addrs: tlv_entries_split(ipv4_addrs),
            ipv6_addrs: tlv_entries_split(ipv6_addrs),
            padding: Default::default(),
            unknown: Default::default(),
        }
    }

    // Returns an iterator over all area addresses from TLVs of type 1.
    pub(crate) fn area_addrs(&self) -> impl Iterator<Item = &AreaAddr> {
        self.area_addrs.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IS neighbors from TLVs of type 6.
    pub(crate) fn neighbors(&self) -> impl Iterator<Item = &[u8; 6]> {
        self.neighbors.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IPv4 addresses from TLVs of type 132.
    pub(crate) fn ipv4_addrs(&self) -> impl Iterator<Item = &Ipv4Addr> {
        self.ipv4_addrs.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IPv6 addresses from TLVs of type 232.
    pub(crate) fn ipv6_addrs(&self) -> impl Iterator<Item = &Ipv6Addr> {
        self.ipv6_addrs.iter().flat_map(|tlv| tlv.list.iter())
    }
}

// ===== impl Lsp =====

impl Lsp {
    pub const HEADER_LEN: u8 = 27;

    pub fn new(
        level: LevelNumber,
        rem_lifetime: u16,
        lsp_id: LspId,
        seqno: u32,
        flags: LspFlags,
        tlvs: LspTlvs,
    ) -> Self {
        let pdu_type = match level {
            LevelNumber::L1 => PduType::LspL1,
            LevelNumber::L2 => PduType::LspL2,
        };
        let mut lsp = Lsp {
            hdr: Header::new(pdu_type),
            rem_lifetime,
            lsp_id,
            seqno,
            cksum: 0,
            flags,
            tlvs,
            raw: Default::default(),
            base_time: lsp_base_time(),
        };
        lsp.encode();
        lsp
    }

    fn decode(
        hdr: Header,
        packet_len: usize,
        buf: &mut Bytes,
    ) -> DecodeResult<Self> {
        // Parse PDU length.
        let pdu_len = buf.get_u16();
        if pdu_len != packet_len as u16 {
            return Err(DecodeError::InvalidPduLength(pdu_len));
        }

        // Parse remaining lifetime.
        let rem_lifetime = buf.get_u16();

        // Parse LSP ID.
        let lsp_id = LspId::decode(buf);

        // Parse sequence number.
        let seqno = buf.get_u32();

        // Parse checksum.
        let cksum = buf.get_u16();

        // Parse flags.
        let flags = buf.get_u8();
        let flags = LspFlags::from_bits_truncate(flags);

        // Parse top-level TLVs.
        let mut tlvs = LspTlvs::default();
        while buf.remaining() >= TLV_HDR_SIZE {
            // Parse TLV type.
            let tlv_type = buf.get_u8();
            let tlv_etype = TlvType::from_u8(tlv_type);

            // Parse and validate TLV length.
            let tlv_len = buf.get_u8();
            if tlv_len as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            // Parse TLV value.
            let mut buf_tlv = buf.copy_to_bytes(tlv_len as usize);
            match tlv_etype {
                Some(TlvType::AreaAddresses) => {
                    let tlv = AreaAddressesTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.area_addrs.push(tlv);
                }
                Some(TlvType::LspBufferSize) => {
                    let tlv = LspBufferSizeTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.lsp_buf_size = Some(tlv);
                }
                Some(TlvType::IsReach) => {
                    let tlv = IsReachTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.is_reach.push(tlv);
                }
                Some(TlvType::ExtIsReach) => {
                    let tlv = ExtIsReachTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.ext_is_reach.push(tlv);
                }
                Some(TlvType::Ipv4InternalReach) => {
                    let tlv = Ipv4ReachTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.ipv4_internal_reach.push(tlv);
                }
                Some(TlvType::ProtocolsSupported) => {
                    if tlvs.protocols_supported.is_some() {
                        continue;
                    }
                    let tlv =
                        ProtocolsSupportedTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.protocols_supported = Some(tlv);
                }
                Some(TlvType::Ipv4ExternalReach) => {
                    let tlv = Ipv4ReachTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.ipv4_external_reach.push(tlv);
                }
                Some(TlvType::Ipv4Addresses) => {
                    let tlv = Ipv4AddressesTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.ipv4_addrs.push(tlv);
                }
                Some(TlvType::ExtIpv4Reach) => {
                    let tlv = ExtIpv4ReachTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.ext_ipv4_reach.push(tlv);
                }
                Some(TlvType::Ipv6Addresses) => {
                    let tlv = Ipv6AddressesTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.ipv6_addrs.push(tlv);
                }
                Some(TlvType::Ipv6Reach) => {
                    let tlv = Ipv6ReachTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.ipv6_reach.push(tlv);
                }
                _ => {
                    // Save unknown top-level TLV.
                    let value = buf_tlv.copy_to_bytes(tlv_len as usize);
                    tlvs.unknown
                        .push(UnknownTlv::new(tlv_type, tlv_len, value));
                }
            }
        }

        Ok(Lsp {
            hdr,
            rem_lifetime,
            lsp_id,
            seqno,
            cksum,
            flags,
            tlvs,
            raw: Default::default(),
            base_time: lsp_base_time(),
        })
    }

    fn encode(&mut self) -> Bytes {
        TLS_BUF.with(|buf| {
            let mut buf = pdu_encode_start(buf, &self.hdr);

            // The PDU length will be initialized later.
            let len_pos = buf.len();
            buf.put_u16(0);
            buf.put_u16(self.rem_lifetime);
            self.lsp_id.encode(&mut buf);
            buf.put_u32(self.seqno);
            // The checksum will be initialized later.
            buf.put_u16(0);
            buf.put_u8(self.flags.bits());

            // Encode TLVs.
            if let Some(tlv) = &self.tlvs.protocols_supported {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.area_addrs {
                tlv.encode(&mut buf);
            }
            if let Some(tlv) = &self.tlvs.lsp_buf_size {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.is_reach {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.ext_is_reach {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.ipv4_addrs {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.ipv4_internal_reach {
                tlv.encode(TlvType::Ipv4InternalReach, &mut buf);
            }
            for tlv in &self.tlvs.ipv4_external_reach {
                tlv.encode(TlvType::Ipv4ExternalReach, &mut buf);
            }
            for tlv in &self.tlvs.ext_ipv4_reach {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.ipv6_addrs {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.ipv6_reach {
                tlv.encode(&mut buf);
            }

            // Compute LSP checksum.
            let cksum = Self::checksum(&buf[12..]);
            buf[24..26].copy_from_slice(&cksum);
            self.cksum = u16::from_be_bytes(cksum);

            // Store LSP raw data.
            let bytes = pdu_encode_end(buf, len_pos);
            self.raw = bytes.clone();
            bytes
        })
    }

    // Computes the LSP checksum.
    fn checksum(data: &[u8]) -> [u8; 2] {
        let checksum = fletcher::calc_fletcher16(data);
        let mut checkbyte0 = (checksum & 0x00FF) as i32;
        let mut checkbyte1 = ((checksum >> 8) & 0x00FF) as i32;

        // Adjust checksum value using scaling factor.
        let sop = data.len() as u16 - 13;
        let mut x = (sop as i32 * checkbyte0 - checkbyte1) % 255;
        if x <= 0 {
            x += 255;
        }
        checkbyte1 = 510 - checkbyte0 - x;
        if checkbyte1 > 255 {
            checkbyte1 -= 255;
        }
        checkbyte0 = x;
        [checkbyte0 as u8, checkbyte1 as u8]
    }

    // Checks if the LSP checksum is valid.
    pub(crate) fn is_checksum_valid(&self) -> bool {
        // Skip checksum validation in testing mode if the checksum field is set
        // to zero.
        #[cfg(feature = "testing")]
        {
            if self.cksum == 0 {
                return true;
            }
        }

        // If both are zero return correct.
        if self.raw[24..26] == [0, 0] {
            return true;
        }

        // If either, but not both are zero return incorrect.
        if self.raw[24] == 0 || self.raw[25] == 0 {
            return true;
        }

        // Skip everything before (and including) the Remaining Lifetime field.
        fletcher::calc_fletcher16(&self.raw[12..]) == 0
    }

    // Returns the current LSP remaining lifetime.
    pub(crate) fn rem_lifetime(&self) -> u16 {
        let mut rem_lifetime = self.rem_lifetime;

        if let Some(base_time) = self.base_time {
            let elapsed = u16::try_from(base_time.elapsed().as_secs())
                .unwrap_or(u16::MAX);
            rem_lifetime = rem_lifetime.saturating_sub(elapsed);
        }

        rem_lifetime
    }

    // Updates the LSP remaining lifetime.
    pub(crate) fn set_rem_lifetime(&mut self, rem_lifetime: u16) {
        // Update Remaining Lifetime field.
        self.rem_lifetime = rem_lifetime;

        // Update raw data.
        let mut raw = BytesMut::from(self.raw.as_ref());
        raw[10..12].copy_from_slice(&rem_lifetime.to_be_bytes());
        self.raw = raw.freeze();

        // Update base time.
        self.base_time = lsp_base_time();
    }

    // Converts the LSP into an LSP Entry for use in an SNP.
    pub(crate) fn as_snp_entry(&self) -> LspEntry {
        LspEntry {
            rem_lifetime: self.rem_lifetime,
            lsp_id: self.lsp_id,
            seqno: self.seqno,
            cksum: self.cksum,
        }
    }
}

impl LspTlvs {
    pub(crate) fn new(
        protocols_supported: impl IntoIterator<Item = u8>,
        area_addrs: impl IntoIterator<Item = AreaAddr>,
        lsp_buf_size: Option<u16>,
        is_reach: impl IntoIterator<Item = IsReach>,
        ext_is_reach: impl IntoIterator<Item = ExtIsReach>,
        ipv4_addrs: impl IntoIterator<Item = Ipv4Addr>,
        ipv4_internal_reach: impl IntoIterator<Item = Ipv4Reach>,
        ipv4_external_reach: impl IntoIterator<Item = Ipv4Reach>,
        ext_ipv4_reach: impl IntoIterator<Item = ExtIpv4Reach>,
        ipv6_addrs: impl IntoIterator<Item = Ipv6Addr>,
        ipv6_reach: impl IntoIterator<Item = Ipv6Reach>,
    ) -> Self {
        LspTlvs {
            protocols_supported: Some(ProtocolsSupportedTlv::from(
                protocols_supported,
            )),
            area_addrs: tlv_entries_split(area_addrs),
            lsp_buf_size: lsp_buf_size.map(|size| LspBufferSizeTlv { size }),
            is_reach: tlv_entries_split(is_reach),
            ext_is_reach: tlv_entries_split(ext_is_reach),
            ipv4_addrs: tlv_entries_split(ipv4_addrs),
            ipv4_internal_reach: tlv_entries_split(ipv4_internal_reach),
            ipv4_external_reach: tlv_entries_split(ipv4_external_reach),
            ext_ipv4_reach: tlv_entries_split(ext_ipv4_reach),
            ipv6_addrs: tlv_entries_split(ipv6_addrs),
            ipv6_reach: tlv_entries_split(ipv6_reach),
            unknown: Default::default(),
        }
    }

    pub(crate) fn next_chunk(&mut self, max_len: usize) -> Option<Self> {
        let mut rem_len = max_len;
        let protocols_supported = self.protocols_supported.take();
        if let Some(protocols_supported) = &protocols_supported {
            rem_len -= protocols_supported.len();
        }
        let area_addrs = tlv_take_max(&mut self.area_addrs, &mut rem_len);
        let lsp_buf_size = self.lsp_buf_size.take();
        if let Some(lsp_buf_size) = &lsp_buf_size {
            rem_len -= lsp_buf_size.len();
        }
        let is_reach = tlv_take_max(&mut self.is_reach, &mut rem_len);
        let ext_is_reach = tlv_take_max(&mut self.ext_is_reach, &mut rem_len);
        let ipv4_addrs = tlv_take_max(&mut self.ipv4_addrs, &mut rem_len);
        let ipv4_internal_reach =
            tlv_take_max(&mut self.ipv4_internal_reach, &mut rem_len);
        let ipv4_external_reach =
            tlv_take_max(&mut self.ipv4_external_reach, &mut rem_len);
        let ext_ipv4_reach =
            tlv_take_max(&mut self.ext_ipv4_reach, &mut rem_len);
        let ipv6_addrs = tlv_take_max(&mut self.ipv6_addrs, &mut rem_len);
        let ipv6_reach = tlv_take_max(&mut self.ipv6_reach, &mut rem_len);
        if rem_len == max_len {
            return None;
        }

        Some(LspTlvs {
            protocols_supported,
            area_addrs,
            lsp_buf_size,
            is_reach,
            ext_is_reach,
            ipv4_addrs,
            ipv4_internal_reach,
            ipv4_external_reach,
            ext_ipv4_reach,
            ipv6_addrs,
            ipv6_reach,
            unknown: Default::default(),
        })
    }

    // Returns an iterator over all supported protocols from the TLV of type 129.
    pub(crate) fn protocols_supported(&self) -> impl Iterator<Item = u8> + '_ {
        self.protocols_supported
            .iter()
            .flat_map(|tlv| tlv.list.iter())
            .copied()
    }

    // Returns an iterator over all area addresses from TLVs of type 1.
    #[expect(unused)]
    pub(crate) fn area_addrs(&self) -> impl Iterator<Item = &AreaAddr> {
        self.area_addrs.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns the maximum sized LSP which may be generated (TLV type 14).
    pub(crate) fn lsp_buf_size(&self) -> Option<u16> {
        self.lsp_buf_size.as_ref().map(|tlv| tlv.size)
    }

    // Returns an iterator over all IS neighbors from TLVs of type 2.
    pub(crate) fn is_reach(&self) -> impl Iterator<Item = &IsReach> {
        self.is_reach.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IS neighbors from TLVs of type 22.
    pub(crate) fn ext_is_reach(&self) -> impl Iterator<Item = &ExtIsReach> {
        self.ext_is_reach.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IPv4 addresses from TLVs of type 132.
    pub(crate) fn ipv4_addrs(&self) -> impl Iterator<Item = &Ipv4Addr> {
        self.ipv4_addrs.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IPv4 internal reachability entries from TLVs
    // of type 128.
    pub(crate) fn ipv4_internal_reach(
        &self,
    ) -> impl Iterator<Item = &Ipv4Reach> {
        self.ipv4_internal_reach
            .iter()
            .flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IPv4 external reachability entries from TLVs
    // of type 130.
    pub(crate) fn ipv4_external_reach(
        &self,
    ) -> impl Iterator<Item = &Ipv4Reach> {
        self.ipv4_external_reach
            .iter()
            .flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IPv4 reachability entries from TLVs of
    // type 135.
    pub(crate) fn ext_ipv4_reach(&self) -> impl Iterator<Item = &ExtIpv4Reach> {
        self.ext_ipv4_reach.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IPv6 addresses from TLVs of type 232.
    pub(crate) fn ipv6_addrs(&self) -> impl Iterator<Item = &Ipv6Addr> {
        self.ipv6_addrs.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IPv6 reachability entries from TLVs of
    // type 236.
    pub(crate) fn ipv6_reach(&self) -> impl Iterator<Item = &Ipv6Reach> {
        self.ipv6_reach.iter().flat_map(|tlv| tlv.list.iter())
    }
}

// ===== impl Snp =====

impl Snp {
    pub const CSNP_HEADER_LEN: u8 = 33;
    pub const PSNP_HEADER_LEN: u8 = 17;

    pub fn new(
        level: LevelNumber,
        source: LanId,
        summary: Option<(LspId, LspId)>,
        tlvs: SnpTlvs,
    ) -> Self {
        let pdu_type = match (summary.is_some(), level) {
            (false, LevelNumber::L1) => PduType::PsnpL1,
            (false, LevelNumber::L2) => PduType::PsnpL2,
            (true, LevelNumber::L1) => PduType::CsnpL1,
            (true, LevelNumber::L2) => PduType::CsnpL2,
        };
        Snp {
            hdr: Header::new(pdu_type),
            source,
            summary,
            tlvs,
        }
    }

    fn decode(
        hdr: Header,
        packet_len: usize,
        buf: &mut Bytes,
    ) -> DecodeResult<Self> {
        // Parse PDU length.
        let pdu_len = buf.get_u16();
        if pdu_len != packet_len as u16 {
            return Err(DecodeError::InvalidPduLength(pdu_len));
        }

        // Parse source ID.
        let source = LanId::decode(buf);

        // Parse start and end LSP IDs.
        let mut summary = None;
        if matches!(hdr.pdu_type, PduType::CsnpL1 | PduType::CsnpL2) {
            let start_lsp_id = LspId::decode(buf);
            let end_lsp_id = LspId::decode(buf);
            summary = Some((start_lsp_id, end_lsp_id));
        }

        // Parse top-level TLVs.
        let mut tlvs = SnpTlvs::default();
        while buf.remaining() >= TLV_HDR_SIZE {
            // Parse TLV type.
            let tlv_type = buf.get_u8();
            let tlv_etype = TlvType::from_u8(tlv_type);

            // Parse and validate TLV length.
            let tlv_len = buf.get_u8();
            if tlv_len as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            // Parse TLV value.
            let mut buf_tlv = buf.copy_to_bytes(tlv_len as usize);
            match tlv_etype {
                Some(TlvType::LspEntries) => {
                    let tlv = LspEntriesTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.lsp_entries.push(tlv);
                }
                _ => {
                    // Save unknown top-level TLV.
                    let value = buf_tlv.copy_to_bytes(tlv_len as usize);
                    tlvs.unknown
                        .push(UnknownTlv::new(tlv_type, tlv_len, value));
                }
            }
        }

        Ok(Snp {
            hdr,
            source,
            summary,
            tlvs,
        })
    }

    fn encode(&self) -> Bytes {
        TLS_BUF.with(|buf| {
            let mut buf = pdu_encode_start(buf, &self.hdr);

            // The PDU length will be initialized later.
            let len_pos = buf.len();
            buf.put_u16(0);
            self.source.encode(&mut buf);

            if let Some((start_lsp_id, end_lsp_id)) = &self.summary {
                start_lsp_id.encode(&mut buf);
                end_lsp_id.encode(&mut buf);
            }

            // Encode TLVs.
            for tlv in &self.tlvs.lsp_entries {
                tlv.encode(&mut buf);
            }

            pdu_encode_end(buf, len_pos)
        })
    }
}

impl SnpTlvs {
    pub(crate) fn new(lsp_entries: impl IntoIterator<Item = LspEntry>) -> Self {
        // Fragment TLVs as necessary.
        let lsp_entries = lsp_entries
            .into_iter()
            .collect::<Vec<_>>()
            .chunks(LspEntriesTlv::MAX_ENTRIES)
            .map(|chunk| LspEntriesTlv {
                list: chunk.to_vec(),
            })
            .collect();

        SnpTlvs {
            lsp_entries,
            unknown: Default::default(),
        }
    }

    // Calculates the maximum number of LSP entries that can fit within the
    // given size.
    pub(crate) const fn max_lsp_entries(mut size: usize) -> usize {
        let mut lsp_entries = 0;

        // Calculate how many full TLVs fit in the available size.
        let full_tlvs = size / LspEntriesTlv::MAX_SIZE;

        // Update the remaining size after accounting for all full TLVs.
        size %= LspEntriesTlv::MAX_SIZE;

        // Add the number of LSP entries from all full TLVs.
        lsp_entries +=
            full_tlvs * (LspEntriesTlv::MAX_SIZE / LspEntriesTlv::ENTRY_SIZE);

        // Check if the remaining size has enough room for a partial TLV.
        if size >= (TLV_HDR_SIZE + LspEntriesTlv::ENTRY_SIZE) {
            // Add the number of LSP entries from the remaining partial TLV.
            lsp_entries += (size - TLV_HDR_SIZE) / LspEntriesTlv::ENTRY_SIZE;
        }

        lsp_entries
    }

    // Returns an iterator over all LSP entries from TLVs of type 9.
    pub(crate) fn lsp_entries(&self) -> impl Iterator<Item = &LspEntry> {
        self.lsp_entries.iter().flat_map(|tlv| tlv.list.iter())
    }
}

// ===== helper functions =====

fn lsp_base_time() -> Option<Instant> {
    #[cfg(not(feature = "testing"))]
    {
        Some(Instant::now())
    }
    #[cfg(feature = "testing")]
    {
        None
    }
}

fn pdu_encode_start<'a>(
    buf: &'a RefCell<BytesMut>,
    hdr: &Header,
) -> RefMut<'a, BytesMut> {
    let mut buf = buf.borrow_mut();
    buf.clear();
    hdr.encode(&mut buf);
    buf
}

fn pdu_encode_end(mut buf: RefMut<'_, BytesMut>, len_pos: usize) -> Bytes {
    // Initialize PDU length.
    let pkt_len = buf.len() as u16;
    buf[len_pos..len_pos + 2].copy_from_slice(&pkt_len.to_be_bytes());

    buf.clone().freeze()
}
