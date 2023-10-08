//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::AtomicU32;
use std::sync::Arc;
use std::time::Duration;

use holo_northbound::paths::control_plane_protocol::mpls_ldp;
use holo_utils::socket::{UdpSocket, UdpSocketExt};
use holo_utils::task::IntervalTask;
use ipnetwork::{Ipv4Network, Ipv6Network};

use crate::collections::{InterfaceId, InterfaceIndex};
use crate::debug::{Debug, InterfaceInactiveReason};
use crate::error::{Error, IoError};
use crate::instance::{InstanceState, InstanceUp};
use crate::packet::messages::hello::{
    HelloFlags, HelloMsg, TlvCommonHelloParams, TlvConfigSeqNo,
    TlvIpv4TransAddr,
};
use crate::packet::messages::notification::StatusCode;
use crate::packet::Pdu;
use crate::{discovery, network, tasks};

#[derive(Debug)]
pub struct Interface {
    pub id: InterfaceId,
    pub name: String,
    pub system: InterfaceSys,
    pub config: InterfaceCfg,
    pub state: Option<InterfaceState>,
}

#[derive(Debug, Default)]
pub struct InterfaceSys {
    pub operative: bool,
    pub ifindex: Option<u32>,
    pub ipv4_addr_list: BTreeSet<Ipv4Network>,
    pub ipv6_addr_list: BTreeSet<Ipv6Network>,
}

#[derive(Debug)]
pub struct InterfaceCfg {
    pub hello_holdtime: u16,
    pub hello_interval: u16,
    pub ipv4: Option<InterfaceIpv4Cfg>,
}

#[derive(Debug)]
pub struct InterfaceIpv4Cfg {
    pub enabled: bool,
}

#[derive(Debug)]
pub struct InterfaceState {
    // UDP discovery socket bound to this interface.
    pub disc_socket: Arc<UdpSocket>,
    // Hello Tx interval task.
    pub hello_interval_task: IntervalTask,
}

// ===== impl Interface =====

impl Interface {
    const DFLT_ADJ_HOLDTIME: u16 = 15;

    pub(crate) fn new(id: InterfaceId, name: String) -> Interface {
        Debug::InterfaceCreate(&name).log();

        Interface {
            id,
            name,
            system: InterfaceSys::default(),
            config: InterfaceCfg::default(),
            state: None,
        }
    }

    fn start(&mut self, instance_state: &InstanceState) -> Result<(), Error> {
        Debug::InterfaceStart(&self.name).log();

        let disc_socket = network::udp::interface_discovery_socket(self)
            .map(Arc::new)
            .map_err(IoError::UdpSocketError)?;

        self.system
            .join_multicast_ipv4(&instance_state.ipv4.disc_socket);
        let hello_interval_task =
            tasks::iface_hello_interval(self, &disc_socket, instance_state);

        self.state = Some(InterfaceState {
            disc_socket,
            hello_interval_task,
        });

        Ok(())
    }

    pub(crate) fn stop(
        instance: &mut InstanceUp,
        iface_idx: InterfaceIndex,
        reason: InterfaceInactiveReason,
    ) {
        let iface = &mut instance.core.interfaces[iface_idx];
        let iface_id = iface.id;

        Debug::InterfaceStop(&iface.name, reason).log();

        iface
            .system
            .leave_multicast_ipv4(&instance.state.ipv4.disc_socket);
        iface.state = None;
        Interface::delete_adjacencies(instance, iface_id);
    }

    // Enables or disables the interface if necessary.
    pub(crate) fn update(instance: &mut InstanceUp, iface_idx: InterfaceIndex) {
        let iface = &mut instance.core.interfaces[iface_idx];

        match iface.is_ready() {
            Ok(()) if !iface.is_active() => {
                // Attempt to activate interface.
                if let Err(error) = iface.start(&instance.state) {
                    Error::InterfaceStartError(
                        iface.name.clone(),
                        Box::new(error),
                    )
                    .log();
                }
            }
            Err(reason) if iface.is_active() => {
                // Deactivate interface.
                Interface::stop(instance, iface_idx, reason);
            }
            _ => (),
        }
    }

    pub(crate) fn sync_hello_tx(&mut self, instance_state: &InstanceState) {
        let state = self.state.as_ref().unwrap();
        let hello_interval_task = tasks::iface_hello_interval(
            self,
            &state.disc_socket,
            instance_state,
        );

        let state = self.state.as_mut().unwrap();
        state.hello_interval_task = hello_interval_task;
    }

    pub(crate) fn is_active(&self) -> bool {
        self.state.is_some()
    }

    // Returns whether the interface is ready for LDP operation.
    fn is_ready(&self) -> Result<(), InterfaceInactiveReason> {
        if self.config.ipv4.is_none()
            || !self.config.ipv4.as_ref().unwrap().enabled
        {
            return Err(InterfaceInactiveReason::AdminDown);
        }

        if !self.system.operative {
            return Err(InterfaceInactiveReason::OperationalDown);
        }

        if self.system.ifindex.is_none() {
            return Err(InterfaceInactiveReason::MissingIfindex);
        }

        if self.system.ipv4_addr_list.is_empty() {
            return Err(InterfaceInactiveReason::MissingIpAddress);
        }

        Ok(())
    }

    pub(crate) fn generate_hello(
        &self,
        instance_state: &InstanceState,
    ) -> HelloMsg {
        HelloMsg {
            // The message ID will be overwritten later.
            msg_id: 0,
            params: TlvCommonHelloParams {
                holdtime: self.config.hello_holdtime,
                flags: HelloFlags::GTSM,
            },
            ipv4_addr: Some(TlvIpv4TransAddr(instance_state.ipv4.trans_addr)),
            ipv6_addr: None,
            cfg_seqno: Some(TlvConfigSeqNo(instance_state.cfg_seqno)),
            dual_stack: None,
        }
    }

    pub(crate) async fn send_hello(
        disc_socket: Arc<UdpSocket>,
        router_id: Ipv4Addr,
        msg_id: Arc<AtomicU32>,
        mut hello: HelloMsg,
    ) {
        // Update hello message ID.
        hello.msg_id = InstanceState::get_next_msg_id(&msg_id);
        Debug::AdjacencyHelloTx(&hello).log();

        // Prepare hello pdu.
        let mut pdu = Pdu::new(router_id, 0);
        pdu.messages.push_back(hello.into());

        // Send multicast packet.
        if let Err(error) =
            network::udp::send_packet_multicast(&disc_socket, pdu).await
        {
            IoError::UdpSendError(error).log();
        }
    }

    pub(crate) fn calculate_adj_holdtime(
        &self,
        mut hello_holdtime: u16,
    ) -> u16 {
        if hello_holdtime == 0 {
            hello_holdtime = Self::DFLT_ADJ_HOLDTIME;
        }

        std::cmp::min(self.config.hello_holdtime, hello_holdtime)
    }

    pub(crate) fn next_hello(&self) -> Option<Duration> {
        self.state
            .as_ref()
            .map(|state| state.hello_interval_task.remaining())
    }

    fn delete_adjacencies(instance: &mut InstanceUp, iface_id: InterfaceId) {
        let adjacencies = &mut instance.state.ipv4.adjacencies;

        for adj_idx in adjacencies
            .get_by_iface(iface_id)
            .iter()
            .flat_map(|adjs| adjs.values().cloned())
            .collect::<Vec<InterfaceIndex>>()
        {
            discovery::adjacency_delete(
                instance,
                adj_idx,
                StatusCode::Shutdown,
            );
        }
    }
}

impl Drop for Interface {
    fn drop(&mut self) {
        Debug::InterfaceDelete(&self.name).log();
    }
}

// ===== impl InterfaceSys =====

impl InterfaceSys {
    // Checks if the interface shares a subnet with the given IP address.
    pub(crate) fn contains_addr(&self, addr: &IpAddr) -> bool {
        match addr {
            IpAddr::V4(addr) => {
                for local in &self.ipv4_addr_list {
                    if local.contains(*addr) {
                        return true;
                    }
                }
            }
            IpAddr::V6(addr) => {
                for local in &self.ipv6_addr_list {
                    if local.contains(*addr) {
                        return true;
                    }
                }
            }
        };

        false
    }

    fn join_multicast_ipv4(&self, disc_socket: &UdpSocket) {
        #[cfg(not(feature = "testing"))]
        {
            if let Err(error) = disc_socket.join_multicast_ifindex_v4(
                &network::udp::LDP_MCAST_ADDR_V4,
                self.ifindex.unwrap(),
            ) {
                IoError::UdpMulticastJoinError(error).log();
            }
        }
    }

    fn leave_multicast_ipv4(&self, disc_socket: &UdpSocket) {
        #[cfg(not(feature = "testing"))]
        {
            if let Err(error) = disc_socket.leave_multicast_ifindex_v4(
                &network::udp::LDP_MCAST_ADDR_V4,
                self.ifindex.unwrap(),
            ) {
                IoError::UdpMulticastJoinError(error).log();
            }
        }
    }

    pub(crate) fn local_ipv4_addr(&self) -> IpAddr {
        let addr = self.ipv4_addr_list.iter().next().unwrap();
        IpAddr::from(addr.ip())
    }
}

// ===== impl InterfaceCfg =====

impl Default for InterfaceCfg {
    fn default() -> InterfaceCfg {
        let hello_holdtime =
            mpls_ldp::discovery::interfaces::hello_holdtime::DFLT;
        let hello_interval =
            mpls_ldp::discovery::interfaces::hello_interval::DFLT;

        InterfaceCfg {
            hello_holdtime,
            hello_interval,
            ipv4: None,
        }
    }
}

// ===== impl InterfaceIpv4Cfg =====

impl Default for InterfaceIpv4Cfg {
    fn default() -> InterfaceIpv4Cfg {
        let enabled =
            mpls_ldp::discovery::interfaces::interface::address_families::ipv4::enabled::DFLT;

        InterfaceIpv4Cfg { enabled }
    }
}
