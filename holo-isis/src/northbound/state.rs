//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

#![allow(unreachable_code)]

use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::{atomic, LazyLock as Lazy};

use enum_as_inner::EnumAsInner;
use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, Provider,
};
use holo_northbound::yang::control_plane_protocol::isis;
use holo_utils::option::OptionExt;
use holo_yang::ToYang;

use crate::adjacency::Adjacency;
use crate::collections::Lsdb;
use crate::instance::Instance;
use crate::interface::Interface;
use crate::lsdb::{LspEntry, LspLogEntry};
use crate::packet::tlv::{
    ExtIpv4Reach, ExtIsReach, Ipv4Reach, IsReach, UnknownTlv,
};
use crate::packet::{LanId, LevelNumber};

pub static CALLBACKS: Lazy<Callbacks<Instance>> = Lazy::new(load_callbacks);

#[derive(Debug, Default)]
#[derive(EnumAsInner)]
pub enum ListEntry<'a> {
    #[default]
    None,
    LspLog(&'a LspLogEntry),
    Lsdb(LevelNumber, &'a Lsdb),
    LspEntry(&'a LspEntry),
    IsReach(&'a LspEntry, LanId),
    IsReachInstance(u32, &'a IsReach),
    ExtIsReach(u32, &'a ExtIsReach),
    Ipv4Reach(&'a Ipv4Reach),
    ExtIpv4Reach(&'a ExtIpv4Reach),
    UnknownTlv(&'a UnknownTlv),
    SystemCounters(LevelNumber),
    Interface(&'a Interface),
    InterfacePacketCounters(&'a Interface, LevelNumber),
    Adjacency(&'a Adjacency),
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Instance> {
    CallbacksBuilder::<Instance>::default()
        .path(isis::PATH)
        .get_object(|instance, _args| {
            use isis::Isis;
            Box::new(Isis {
                discontinuity_time: instance.state.as_ref().map(|state| &state.discontinuity_time).map(Cow::Borrowed).ignore_in_testing(),
            })
        })
        .path(isis::spf_control::ietf_spf_delay::PATH)
        .get_object(|_instance, _args| {
            use isis::spf_control::ietf_spf_delay::IetfSpfDelay;
            Box::new(IetfSpfDelay {
                current_state: None,
                remaining_time_to_learn: None,
                remaining_hold_down: None,
                last_event_received: None,
                next_spf_time: None,
                last_spf_time: None,
            })
        })
        .path(isis::spf_log::event::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .get_object(|_instance, _args| {
            use isis::spf_log::event::Event;
            Box::new(Event {
                id: todo!(),
                spf_type: None,
                level: None,
                schedule_timestamp: None,
                start_timestamp: None,
                end_timestamp: None,
            })
        })
        .path(isis::spf_log::event::trigger_lsp::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .get_object(|_instance, _args| {
            use isis::spf_log::event::trigger_lsp::TriggerLsp;
            Box::new(TriggerLsp {
                lsp: todo!(),
                sequence: None,
            })
        })
        .path(isis::lsp_log::event::PATH)
        .get_iterate(|instance, _args| {
            let Some(instance_state) = &instance.state else { return None };
            let iter = instance_state.lsp_log.iter().map(ListEntry::LspLog);
            Some(Box::new(iter) as _).ignore_in_testing()
        })
        .get_object(|_instance, args| {
            use isis::lsp_log::event::Event;
            let log = args.list_entry.as_lsp_log().unwrap();
            Box::new(Event {
                id: log.id,
                level: Some(log.level as u8),
                received_timestamp: log.rcvd_time.as_ref().map(Cow::Borrowed).ignore_in_testing(),
                reason: Some(log.reason.to_yang()),
            })
        })
        .path(isis::lsp_log::event::lsp::PATH)
        .get_object(|_instance, args| {
            use isis::lsp_log::event::lsp::Lsp;
            let log = args.list_entry.as_lsp_log().unwrap();
            Box::new(Lsp {
                lsp: Some(log.lsp.lsp_id.to_yang()),
                sequence: Some(log.lsp.seqno),
            })
        })
        .path(isis::hostnames::hostname::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .get_object(|_instance, _args| {
            use isis::hostnames::hostname::Hostname;
            Box::new(Hostname {
                system_id: todo!(),
                hostname: None,
            })
        })
        .path(isis::database::levels::PATH)
        .get_iterate(|instance, _args| {
            let Some(instance_state) = &instance.state else { return None };
            let iter = [LevelNumber::L1, LevelNumber::L2].into_iter().map(|level| ListEntry::Lsdb(level, instance_state.lsdb.get(level)));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::Levels;
            let (level, _) = args.list_entry.as_lsdb().unwrap();
            Box::new(Levels {
                level: *level as u8,
            })
        })
        .path(isis::database::levels::lsp::PATH)
        .get_iterate(|instance, args| {
            let (_, lsdb) = args.parent_list_entry.as_lsdb().unwrap();
            let iter = lsdb.iter(&instance.arenas.lsp_entries).map(ListEntry::LspEntry);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::Lsp;
            let lse = args.list_entry.as_lsp_entry().unwrap();
            let lsp = &lse.data;
            let ipv4_addresses = lsp.tlvs.ipv4_addrs().map(Cow::Borrowed);
            let protocol_supported = lsp.tlvs.protocols_supported();
            Box::new(Lsp {
                lsp_id: lsp.lsp_id.to_yang(),
                decoded_completed: None,
                raw_data: Some(lsp.raw.as_ref()).ignore_in_testing(),
                checksum: Some(lsp.cksum).ignore_in_testing(),
                remaining_lifetime: Some(lsp.rem_lifetime()).ignore_in_testing(),
                sequence: Some(lsp.seqno),
                ipv4_addresses: Some(Box::new(ipv4_addresses)),
                ipv6_addresses: None,
                ipv4_te_routerid: None,
                ipv6_te_routerid: None,
                protocol_supported: Some(Box::new(protocol_supported)),
                dynamic_hostname: None,
            })
        })
        .path(isis::database::levels::lsp::attributes::PATH)
        .get_object(|_instance, _args| {
            use isis::database::levels::lsp::attributes::Attributes;
            Box::new(Attributes {
                lsp_flags: None,
            })
        })
        .path(isis::database::levels::lsp::authentication::PATH)
        .get_object(|_instance, _args| {
            use isis::database::levels::lsp::authentication::Authentication;
            Box::new(Authentication {
                authentication_type: None,
                authentication_key: None,
            })
        })
        .path(isis::database::levels::lsp::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse = args.parent_list_entry.as_lsp_entry().unwrap();
            let lsp = &lse.data;
            let iter = lsp.tlvs.unknown.iter().map(ListEntry::UnknownTlv);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::unknown_tlvs::unknown_tlv::UnknownTlv;
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Box::new(UnknownTlv {
                r#type: Some(tlv.tlv_type as u16),
                length: Some(tlv.length as u16),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(isis::database::levels::lsp::is_neighbor::neighbor::PATH)
        .get_iterate(|_instance, args| {
            let lse = args.parent_list_entry.as_lsp_entry().unwrap();
            let lsp = &lse.data;
            let iter = lsp.tlvs.is_reach().map(|reach| reach.neighbor).collect::<HashSet<_>>().into_iter().map(|neighbor| ListEntry::IsReach(lse, neighbor));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::is_neighbor::neighbor::Neighbor;
            let (_, neighbor) = args.list_entry.as_is_reach().unwrap();
            Box::new(Neighbor {
                neighbor_id: neighbor.to_yang(),
            })
        })
        .path(isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::PATH)
        .get_iterate(|_instance, args| {
            let (lse, neighbor) = args.parent_list_entry.as_is_reach().unwrap();
            let lsp = &lse.data;
            let neighbor = *neighbor;
            let iter = lsp.tlvs.is_reach()
                .filter(move |reach| reach.neighbor == neighbor)
                .enumerate().map(|(id, reach)| ListEntry::IsReachInstance(id as u32, reach));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::Instance;
            let (id, _) = args.list_entry.as_is_reach_instance().unwrap();
            Box::new(Instance {
                id: *id,
                i_e: Some(false),
            })
        })
        .path(isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::default_metric::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::default_metric::DefaultMetric;
            let (_, reach) = args.list_entry.as_is_reach_instance().unwrap();
            Box::new(DefaultMetric {
                metric: Some(reach.metric),
            })
        })
        .path(isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::delay_metric::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::delay_metric::DelayMetric;
            let (_, reach) = args.list_entry.as_is_reach_instance().unwrap();
            Box::new(DelayMetric {
                metric: reach.metric_delay,
                supported: Some(reach.metric_delay.is_some()),
            })
        })
        .path(isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::expense_metric::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::expense_metric::ExpenseMetric;
            let (_, reach) = args.list_entry.as_is_reach_instance().unwrap();
            Box::new(ExpenseMetric {
                metric: reach.metric_expense,
                supported: Some(reach.metric_expense.is_some()),
            })
        })
        .path(isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::error_metric::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::error_metric::ErrorMetric;
            let (_, reach) = args.list_entry.as_is_reach_instance().unwrap();
            Box::new(ErrorMetric {
                metric: reach.metric_error,
                supported: Some(reach.metric_error.is_some()),
            })
        })
        .path(isis::database::levels::lsp::extended_is_neighbor::neighbor::PATH)
        .get_iterate(|_instance, args| {
            let lse = args.parent_list_entry.as_lsp_entry().unwrap();
            let lsp = &lse.data;
            let iter = lsp.tlvs.ext_is_reach().enumerate().map(|(id, reach)| ListEntry::ExtIsReach(id as u32, reach));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::extended_is_neighbor::neighbor::Neighbor;
            let (_, reach) = args.list_entry.as_ext_is_reach().unwrap();
            Box::new(Neighbor {
                neighbor_id: reach.neighbor.to_yang(),
            })
        })
        .path(isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::PATH)
        .get_iterate(|_instance, args| {
            let (id, reach) = args.parent_list_entry.as_ext_is_reach().unwrap();
            let iter = std::iter::once(ListEntry::ExtIsReach(*id, reach));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::Instance;
            let (id, reach) = args.list_entry.as_ext_is_reach().unwrap();
            Box::new(Instance {
                id: *id,
                metric: Some(reach.metric),
                admin_group: None,
                te_metric: None,
                max_bandwidth: None,
                max_reservable_bandwidth: None,
            })
        })
        .path(isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::local_if_ipv4_addrs::PATH)
        .get_object(|_instance, _args| {
            use isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::local_if_ipv4_addrs::LocalIfIpv4Addrs;
            Box::new(LocalIfIpv4Addrs {
                local_if_ipv4_addr: None,
            })
        })
        .path(isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::remote_if_ipv4_addrs::PATH)
        .get_object(|_instance, _args| {
            use isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::remote_if_ipv4_addrs::RemoteIfIpv4Addrs;
            Box::new(RemoteIfIpv4Addrs {
                remote_if_ipv4_addr: None,
            })
        })
        .path(isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::unreserved_bandwidths::unreserved_bandwidth::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .get_object(|_instance, _args| {
            use isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::unreserved_bandwidths::unreserved_bandwidth::UnreservedBandwidth;
            Box::new(UnreservedBandwidth {
                priority: None,
                unreserved_bandwidth: None,
            })
        })
        .path(isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, args| {
            let (_, reach) = args.parent_list_entry.as_ext_is_reach().unwrap();
            let iter = reach.sub_tlvs.unknown.iter().map(ListEntry::UnknownTlv);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::unknown_tlvs::unknown_tlv::UnknownTlv;
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Box::new(UnknownTlv {
                r#type: Some(tlv.tlv_type as u16),
                length: Some(tlv.length as u16),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(isis::database::levels::lsp::ipv4_internal_reachability::prefixes::PATH)
        .get_iterate(|_instance, args| {
            let lse = args.parent_list_entry.as_lsp_entry().unwrap();
            let lsp = &lse.data;
            let iter = lsp.tlvs.ipv4_internal_reach().map(ListEntry::Ipv4Reach);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::ipv4_internal_reachability::prefixes::Prefixes;
            let reach = args.list_entry.as_ipv4_reach().unwrap();
            Box::new(Prefixes {
                ip_prefix: Some(Cow::Owned(reach.prefix.ip())),
                prefix_len: Some(reach.prefix.prefix()),
                i_e: Some(reach.ie_bit),
            })
        })
        .path(isis::database::levels::lsp::ipv4_internal_reachability::prefixes::default_metric::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::ipv4_internal_reachability::prefixes::default_metric::DefaultMetric;
            let reach = args.list_entry.as_ipv4_reach().unwrap();
            Box::new(DefaultMetric {
                metric: Some(reach.metric),
            })
        })
        .path(isis::database::levels::lsp::ipv4_internal_reachability::prefixes::delay_metric::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::ipv4_internal_reachability::prefixes::delay_metric::DelayMetric;
            let reach = args.list_entry.as_ipv4_reach().unwrap();
            Box::new(DelayMetric {
                metric: reach.metric_delay,
                supported: Some(reach.metric_delay.is_some()),
            })
        })
        .path(isis::database::levels::lsp::ipv4_internal_reachability::prefixes::expense_metric::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::ipv4_internal_reachability::prefixes::expense_metric::ExpenseMetric;
            let reach = args.list_entry.as_ipv4_reach().unwrap();
            Box::new(ExpenseMetric {
                metric: reach.metric_expense,
                supported: Some(reach.metric_expense.is_some()),
            })
        })
        .path(isis::database::levels::lsp::ipv4_internal_reachability::prefixes::error_metric::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::ipv4_internal_reachability::prefixes::error_metric::ErrorMetric;
            let reach = args.list_entry.as_ipv4_reach().unwrap();
            Box::new(ErrorMetric {
                metric: reach.metric_error,
                supported: Some(reach.metric_error.is_some()),
            })
        })
        .path(isis::database::levels::lsp::ipv4_external_reachability::prefixes::PATH)
        .get_iterate(|_instance, args| {
            let lse = args.parent_list_entry.as_lsp_entry().unwrap();
            let lsp = &lse.data;
            let iter = lsp.tlvs.ipv4_external_reach().map(ListEntry::Ipv4Reach);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::ipv4_external_reachability::prefixes::Prefixes;
            let reach = args.list_entry.as_ipv4_reach().unwrap();
            Box::new(Prefixes {
                ip_prefix: Some(Cow::Owned(reach.prefix.ip())),
                prefix_len: Some(reach.prefix.prefix()),
                i_e: Some(reach.ie_bit),
            })
        })
        .path(isis::database::levels::lsp::ipv4_external_reachability::prefixes::default_metric::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::ipv4_external_reachability::prefixes::default_metric::DefaultMetric;
            let reach = args.list_entry.as_ipv4_reach().unwrap();
            Box::new(DefaultMetric {
                metric: Some(reach.metric),
            })
        })
        .path(isis::database::levels::lsp::ipv4_external_reachability::prefixes::delay_metric::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::ipv4_external_reachability::prefixes::delay_metric::DelayMetric;
            let reach = args.list_entry.as_ipv4_reach().unwrap();
            Box::new(DelayMetric {
                metric: reach.metric_delay,
                supported: Some(reach.metric_delay.is_some()),
            })
        })
        .path(isis::database::levels::lsp::ipv4_external_reachability::prefixes::expense_metric::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::ipv4_external_reachability::prefixes::expense_metric::ExpenseMetric;
            let reach = args.list_entry.as_ipv4_reach().unwrap();
            Box::new(ExpenseMetric {
                metric: reach.metric_expense,
                supported: Some(reach.metric_expense.is_some()),
            })
        })
        .path(isis::database::levels::lsp::ipv4_external_reachability::prefixes::error_metric::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::ipv4_external_reachability::prefixes::error_metric::ErrorMetric;
            let reach = args.list_entry.as_ipv4_reach().unwrap();
            Box::new(ErrorMetric {
                metric: reach.metric_error,
                supported: Some(reach.metric_error.is_some()),
            })
        })
        .path(isis::database::levels::lsp::extended_ipv4_reachability::prefixes::PATH)
        .get_iterate(|_instance, args| {
            let lse = args.parent_list_entry.as_lsp_entry().unwrap();
            let lsp = &lse.data;
            let iter = lsp.tlvs.ext_ipv4_reach().map(ListEntry::ExtIpv4Reach);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::extended_ipv4_reachability::prefixes::Prefixes;
            let reach = args.list_entry.as_ext_ipv4_reach().unwrap();
            Box::new(Prefixes {
                up_down: Some(reach.up_down),
                ip_prefix: Some(Cow::Owned(reach.prefix.ip())),
                prefix_len: Some(reach.prefix.prefix()),
                metric: Some(reach.metric),
            })
        })
        .path(isis::database::levels::lsp::extended_ipv4_reachability::prefixes::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, args| {
            let reach = args.parent_list_entry.as_ext_ipv4_reach().unwrap();
            let iter = reach.sub_tlvs.unknown.iter().map(ListEntry::UnknownTlv);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::extended_ipv4_reachability::prefixes::unknown_tlvs::unknown_tlv::UnknownTlv;
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Box::new(UnknownTlv {
                r#type: Some(tlv.tlv_type as u16),
                length: Some(tlv.length as u16),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(isis::database::levels::lsp::ipv6_reachability::prefixes::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .get_object(|_instance, _args| {
            use isis::database::levels::lsp::ipv6_reachability::prefixes::Prefixes;
            Box::new(Prefixes {
                up_down: None,
                ip_prefix: None,
                prefix_len: None,
                metric: None,
            })
        })
        .path(isis::database::levels::lsp::ipv6_reachability::prefixes::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .get_object(|_instance, _args| {
            use isis::database::levels::lsp::ipv6_reachability::prefixes::unknown_tlvs::unknown_tlv::UnknownTlv;
            Box::new(UnknownTlv {
                r#type: None,
                length: None,
                value: None,
            })
        })
        .path(isis::local_rib::route::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .get_object(|_instance, _args| {
            use isis::local_rib::route::Route;
            Box::new(Route {
                prefix: todo!(),
                metric: None,
                level: None,
                route_tag: None,
            })
        })
        .path(isis::local_rib::route::next_hops::next_hop::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .get_object(|_instance, _args| {
            use isis::local_rib::route::next_hops::next_hop::NextHop;
            Box::new(NextHop {
                next_hop: todo!(),
                outgoing_interface: None,
            })
        })
        .path(isis::system_counters::level::PATH)
        .get_iterate(|_instance, _args| {
            let iter = [LevelNumber::L1, LevelNumber::L2].into_iter().map(ListEntry::SystemCounters);
            Some(Box::new(iter) as _).ignore_in_testing()
        })
        .get_object(|instance, args| {
            use isis::system_counters::level::Level;
            let level = args.list_entry.as_system_counters().unwrap();
            let mut corrupted_lsps = None;
            let mut authentication_type_fails = None;
            let mut authentication_fails = None;
            let mut database_overload = None;
            let mut own_lsp_purge = None;
            let mut manual_address_drop_from_area = None;
            let mut max_sequence = None;
            let mut sequence_number_skipped = None;
            let mut id_len_mismatch = None;
            let mut partition_changes = None;
            let mut lsp_errors = None;
            let mut spf_runs = None;
            if let Some(state) = &instance.state {
                let counters = state.counters.get(*level);
                corrupted_lsps = Some(counters.corrupted_lsps);
                authentication_type_fails = Some(counters.auth_type_fails);
                authentication_fails = Some(counters.auth_fails);
                database_overload = Some(counters.database_overload);
                own_lsp_purge = Some(counters.own_lsp_purge);
                manual_address_drop_from_area = Some(counters.manual_addr_drop_from_area);
                max_sequence = Some(counters.max_sequence);
                sequence_number_skipped = Some(counters.seqno_skipped);
                id_len_mismatch = Some(counters.id_len_mismatch);
                partition_changes = Some(counters.partition_changes);
                lsp_errors = Some(counters.lsp_errors);
                spf_runs = Some(counters.spf_runs);
            }
            Box::new(Level {
                level: *level as u8,
                corrupted_lsps,
                authentication_type_fails,
                authentication_fails,
                database_overload,
                own_lsp_purge,
                manual_address_drop_from_area,
                max_sequence,
                sequence_number_skipped,
                id_len_mismatch,
                partition_changes,
                lsp_errors,
                spf_runs,
            })
        })
        .path(isis::interfaces::interface::PATH)
        .get_iterate(|instance, _args| {
            let iter = instance.arenas.interfaces.iter().map(ListEntry::Interface);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::interfaces::interface::Interface;
            let iface = args.list_entry.as_interface().unwrap();
            let state = if iface.state.active { "up" } else { "down" };
            Box::new(Interface {
                name: Cow::Borrowed(&iface.name),
                discontinuity_time: Some(Cow::Borrowed(&iface.state.discontinuity_time)).ignore_in_testing(),
                state: Some(state.into()),
                circuit_id: Some(iface.state.circuit_id),
            })
        })
        .path(isis::interfaces::interface::adjacencies::adjacency::PATH)
        .get_iterate(|instance, args| {
            let iface = args.parent_list_entry.as_interface().unwrap();
            let iter = iface.state.lan_adjacencies.l1.iter(&instance.arenas.adjacencies).chain(iface.state.lan_adjacencies.l2.iter(&instance.arenas.adjacencies)).chain(iface.state.p2p_adjacency.as_ref()).map(ListEntry::Adjacency);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::interfaces::interface::adjacencies::adjacency::Adjacency;
            let adj = args.list_entry.as_adjacency().unwrap();
            Box::new(Adjacency {
                neighbor_sys_type: Some(adj.level_capability.to_yang()),
                neighbor_sysid: Some(adj.system_id.to_yang()),
                neighbor_extended_circuit_id: None,
                neighbor_snpa: Some(Cow::Owned(format_mac(&adj.snpa))),
                usage: Some(adj.level_usage.to_yang()),
                hold_timer: adj.holdtimer.as_ref().map(|task| task.remaining()).map(Cow::Owned).ignore_in_testing(),
                neighbor_priority: adj.priority,
                lastuptime: adj.last_uptime.as_ref().map(Cow::Borrowed).ignore_in_testing(),
                state: Some(adj.state.to_yang()),
            })
        })
        .path(isis::interfaces::interface::event_counters::PATH)
        .get_object(|_instance, args| {
            use isis::interfaces::interface::event_counters::EventCounters;
            let iface = args.list_entry.as_interface().unwrap();
            Box::new(EventCounters {
                adjacency_changes: Some(iface.state.event_counters.adjacency_changes).ignore_in_testing(),
                adjacency_number: Some(iface.state.event_counters.adjacency_number).ignore_in_testing(),
                init_fails: Some(iface.state.event_counters.init_fails).ignore_in_testing(),
                adjacency_rejects: Some(iface.state.event_counters.adjacency_rejects).ignore_in_testing(),
                id_len_mismatch: Some(iface.state.event_counters.id_len_mismatch).ignore_in_testing(),
                max_area_addresses_mismatch: Some(iface.state.event_counters.max_area_addr_mismatch).ignore_in_testing(),
                authentication_type_fails: Some(iface.state.event_counters.auth_type_fails).ignore_in_testing(),
                authentication_fails: Some(iface.state.event_counters.auth_fails).ignore_in_testing(),
                lan_dis_changes: Some(iface.state.event_counters.lan_dis_changes).ignore_in_testing(),
            })
        })
        .path(isis::interfaces::interface::packet_counters::level::PATH)
        .get_iterate(|_instance, args| {
            let iface = args.parent_list_entry.as_interface().unwrap();
            let iter = [LevelNumber::L1, LevelNumber::L2].into_iter().map(|level| ListEntry::InterfacePacketCounters(iface, level));
            Some(Box::new(iter) as _).ignore_in_testing()
        })
        .get_object(|_instance, args| {
            use isis::interfaces::interface::packet_counters::level::Level;
            let (_, level) = args.list_entry.as_interface_packet_counters().unwrap();
            Box::new(Level {
                level: *level as u8,
            })
        })
        .path(isis::interfaces::interface::packet_counters::level::iih::PATH)
        .get_object(|_instance, args| {
            use isis::interfaces::interface::packet_counters::level::iih::Iih;
            let (iface, level) = args.list_entry.as_interface_packet_counters().unwrap();
            let packet_counters = iface.state.packet_counters.get(*level);
            Box::new(Iih {
                r#in: Some(packet_counters.iih_in),
                out: Some(packet_counters.iih_out.load(atomic::Ordering::Relaxed)),
            })
        })
        .path(isis::interfaces::interface::packet_counters::level::lsp::PATH)
        .get_object(|_instance, args| {
            use isis::interfaces::interface::packet_counters::level::lsp::Lsp;
            let (iface, level) = args.list_entry.as_interface_packet_counters().unwrap();
            let packet_counters = iface.state.packet_counters.get(*level);
            Box::new(Lsp {
                r#in: Some(packet_counters.lsp_in),
                out: Some(packet_counters.lsp_out),
            })
        })
        .path(isis::interfaces::interface::packet_counters::level::psnp::PATH)
        .get_object(|_instance, args| {
            use isis::interfaces::interface::packet_counters::level::psnp::Psnp;
            let (iface, level) = args.list_entry.as_interface_packet_counters().unwrap();
            let packet_counters = iface.state.packet_counters.get(*level);
            Box::new(Psnp {
                r#in: Some(packet_counters.psnp_in),
                out: Some(packet_counters.psnp_out),
            })
        })
        .path(isis::interfaces::interface::packet_counters::level::csnp::PATH)
        .get_object(|_instance, args| {
            use isis::interfaces::interface::packet_counters::level::csnp::Csnp;
            let (iface, level) = args.list_entry.as_interface_packet_counters().unwrap();
            let packet_counters = iface.state.packet_counters.get(*level);
            Box::new(Csnp {
                r#in: Some(packet_counters.csnp_in),
                out: Some(packet_counters.csnp_out),
            })
        })
        .path(isis::interfaces::interface::packet_counters::level::unknown::PATH)
        .get_object(|_instance, args| {
            use isis::interfaces::interface::packet_counters::level::unknown::Unknown;
            let (iface, level) = args.list_entry.as_interface_packet_counters().unwrap();
            let packet_counters = iface.state.packet_counters.get(*level);
            Box::new(Unknown {
                r#in: Some(packet_counters.unknown_in),
            })
        })
        .build()
}

// ===== impl Instance =====

impl Provider for Instance {
    const STATE_PATH: &'static str = "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='ietf-bgp:bgp'][name='test']/ietf-isis:isis";

    type ListEntry<'a> = ListEntry<'a>;

    fn callbacks() -> Option<&'static Callbacks<Instance>> {
        Some(&CALLBACKS)
    }
}

// ===== impl ListEntry =====

impl ListEntryKind for ListEntry<'_> {}

// ===== helper functions =====

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}