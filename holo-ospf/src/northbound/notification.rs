//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;

use holo_northbound::{notification, paths};
use holo_yang::ToYang;

use crate::error::InterfaceCfgError;
use crate::gr::GrExitReason;
use crate::instance::InstanceUpView;
use crate::interface::Interface;
use crate::neighbor::Neighbor;
use crate::packet::error::LsaValidationError;
use crate::packet::PacketType;
use crate::version::Version;

// ===== global functions =====

pub(crate) fn if_state_change<V>(
    instance: &InstanceUpView<'_, V>,
    iface: &Interface<V>,
) where
    V: Version,
{
    use paths::if_state_change::interface::Interface;
    use paths::if_state_change::{self, IfStateChange};

    let data = IfStateChange {
        routing_protocol_name: Some(instance.name.into()),
        address_family: Some(instance.state.af.to_yang()),
        interface: Some(Interface {
            interface: Some(iface.name.as_str().into()),
        }),
        state: Some(iface.state.ism_state.to_yang()),
    };
    notification::send(&instance.tx.nb, if_state_change::PATH, data);
}

pub(crate) fn if_config_error<V>(
    instance: &InstanceUpView<'_, V>,
    ifname: &str,
    src: &V::NetIpAddr,
    pkt_type: &PacketType,
    error: &InterfaceCfgError,
) where
    V: Version,
{
    use paths::if_config_error::interface::Interface;
    use paths::if_config_error::{self, IfConfigError};

    let data = IfConfigError {
        routing_protocol_name: Some(instance.name.into()),
        address_family: Some(instance.state.af.to_yang()),
        interface: Some(Interface {
            interface: Some(ifname.into()),
        }),
        packet_source: Some(src.to_string().into()),
        packet_type: Some(pkt_type.to_yang()),
        error: Some(error.to_yang()),
    };
    notification::send(&instance.tx.nb, if_config_error::PATH, data);
}

pub(crate) fn nbr_state_change<V>(
    instance: &InstanceUpView<'_, V>,
    iface: &Interface<V>,
    nbr: &Neighbor<V>,
) where
    V: Version,
{
    use paths::nbr_state_change::interface::Interface;
    use paths::nbr_state_change::{self, NbrStateChange};

    let data = NbrStateChange {
        routing_protocol_name: Some(instance.name.into()),
        address_family: Some(instance.state.af.to_yang()),
        interface: Some(Interface {
            interface: Some(iface.name.as_str().into()),
        }),
        neighbor_router_id: Some(nbr.router_id.to_string().into()),
        neighbor_ip_addr: Some(nbr.src.to_string().into()),
        state: Some(nbr.state.to_yang()),
    };
    notification::send(&instance.tx.nb, nbr_state_change::PATH, data);
}

pub(crate) fn nbr_restart_helper_enter<V>(
    instance: &InstanceUpView<'_, V>,
    iface: &Interface<V>,
    nbr: &Neighbor<V>,
    age: u32,
) where
    V: Version,
{
    use paths::nbr_restart_helper_status_change::interface::Interface;
    use paths::nbr_restart_helper_status_change::{
        self, NbrRestartHelperStatusChange,
    };

    let data = NbrRestartHelperStatusChange {
        routing_protocol_name: Some(instance.name.into()),
        address_family: Some(instance.state.af.to_yang()),
        interface: Some(Interface {
            interface: Some(iface.name.as_str().into()),
        }),
        neighbor_router_id: Some(nbr.router_id.to_string().into()),
        neighbor_ip_addr: Some(nbr.src.to_string().into()),
        status: Some("helping".into()),
        age: Some(age.to_string().into()),
        exit_reason: None,
    };
    notification::send(
        &instance.tx.nb,
        nbr_restart_helper_status_change::PATH,
        data,
    );
}

pub(crate) fn nbr_restart_helper_exit<V>(
    instance: &InstanceUpView<'_, V>,
    iface: &Interface<V>,
    nbr: &Neighbor<V>,
    reason: GrExitReason,
) where
    V: Version,
{
    use paths::nbr_restart_helper_status_change::interface::Interface;
    use paths::nbr_restart_helper_status_change::{
        self, NbrRestartHelperStatusChange,
    };

    let data = NbrRestartHelperStatusChange {
        routing_protocol_name: Some(instance.name.into()),
        address_family: Some(instance.state.af.to_yang()),
        interface: Some(Interface {
            interface: Some(iface.name.as_str().into()),
        }),
        neighbor_router_id: Some(nbr.router_id.to_string().into()),
        neighbor_ip_addr: Some(nbr.src.to_string().into()),
        status: Some("not-helping".into()),
        age: None,
        exit_reason: Some(reason.to_yang()),
    };
    notification::send(
        &instance.tx.nb,
        nbr_restart_helper_status_change::PATH,
        data,
    );
}

pub(crate) fn if_rx_bad_packet<V>(
    instance: &InstanceUpView<'_, V>,
    iface: &Interface<V>,
    src: V::NetIpAddr,
) where
    V: Version,
{
    use paths::if_rx_bad_packet::interface::Interface;
    use paths::if_rx_bad_packet::{self, IfRxBadPacket};

    let data = IfRxBadPacket {
        routing_protocol_name: Some(instance.name.into()),
        address_family: Some(instance.state.af.to_yang()),
        interface: Some(Interface {
            interface: Some(iface.name.as_str().into()),
        }),
        packet_source: Some(src.to_string().into()),
        // TODO: set the packet-type whenever possible.
        packet_type: None,
    };
    notification::send(&instance.tx.nb, if_rx_bad_packet::PATH, data);
}

pub(crate) fn if_rx_bad_lsa<V>(
    instance: &InstanceUpView<'_, V>,
    src: V::NetIpAddr,
    error: LsaValidationError,
) where
    V: Version,
{
    use paths::if_rx_bad_lsa::{self, IfRxBadLsa};

    let data = IfRxBadLsa {
        routing_protocol_name: Some(instance.name.into()),
        packet_source: Some(src.to_string().into()),
        error: Some(error.to_yang()),
    };
    notification::send(&instance.tx.nb, if_rx_bad_lsa::PATH, data);
}

pub(crate) fn sr_index_out_of_range<V>(
    instance: &InstanceUpView<'_, V>,
    nbr_router_id: Ipv4Addr,
    index: u32,
) where
    V: Version,
{
    use paths::segment_routing_index_out_of_range::{
        self, SegmentRoutingIndexOutOfRange,
    };

    let data = SegmentRoutingIndexOutOfRange {
        received_target: Some(nbr_router_id.to_string().into()),
        received_index: Some(index.to_string().into()),
        routing_protocol: Some(instance.name.into()),
    };
    notification::send(
        &instance.tx.nb,
        segment_routing_index_out_of_range::PATH,
        data,
    );
}
