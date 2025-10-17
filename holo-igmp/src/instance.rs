//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use holo_protocol::{
    InstanceChannelsTx, InstanceShared, MessageReceiver, ProtocolInstance,
};
use holo_utils::ibus::IbusMsg;
use holo_utils::protocol::Protocol;
use holo_utils::socket::{AsyncFd, Socket};
use holo_utils::task::Task;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::debug::Debug;
use crate::error::{Error, IoError};
use crate::interface::Interface;
use crate::northbound::configuration::InstanceCfg;
use crate::tasks::messages::input::NetRxPacketMsg;
use crate::tasks::messages::{ProtocolInputMsg, ProtocolOutputMsg};
use crate::{events, ibus, network, tasks};

pub type Interfaces = BTreeMap<String, Interface>;

#[derive(Debug)]
pub struct Instance {
    // Instance name.
    pub name: String,
    // Instance system data.
    pub system: InstanceSys,
    // Instance configuration data.
    pub config: InstanceCfg,
    // Instance state data.
    pub state: Option<InstanceState>,
    // Instance interfaces.
    pub interfaces: Interfaces,
    // Instance Tx channels.
    pub tx: InstanceChannelsTx<Instance>,
    // Shared data.
    pub shared: InstanceShared,
}

#[derive(Debug, Default)]
pub struct InstanceSys {}

#[derive(Debug)]
pub struct InstanceState {
    pub net: InstanceNet,
    pub statistics: Statistics,
}

#[derive(Debug)]
pub struct InstanceNet {
    pub socket_rx: Arc<AsyncFd<Socket>>,
    _net_rx_task: Task<()>,
}

#[derive(Debug, Default)]
pub struct Statistics {
    pub discontinuity_time: DateTime<Utc>,
    pub errors: ErrorStatistics,
    pub msgs_rcvd: MessageStatistics,
    pub msgs_sent: MessageStatistics,
}

#[derive(Debug, Default)]
pub struct ErrorStatistics {
    pub total: u64,
    pub query: u64,
    pub report: u64,
    pub leave: u64,
    pub checksum: u64,
    pub too_short: u64,
}

#[derive(Debug, Default)]
pub struct MessageStatistics {
    pub total: u64,
    pub query: u64,
    pub report: u64,
    pub leave: u64,
}

#[derive(Clone, Debug)]
pub struct ProtocolInputChannelsTx {
    // Packet Rx event.
    pub net_packet_rx: Sender<NetRxPacketMsg>,
}

#[derive(Debug)]
pub struct ProtocolInputChannelsRx {
    // Packet Rx event.
    pub net_packet_rx: Receiver<NetRxPacketMsg>,
}

pub struct InstanceUpView<'a> {
    pub name: &'a str,
    pub system: &'a InstanceSys,
    pub config: &'a InstanceCfg,
    pub state: &'a mut InstanceState,
    pub tx: &'a InstanceChannelsTx<Instance>,
    pub shared: &'a InstanceShared,
}

// ===== impl Instance =====

impl Instance {
    pub(crate) fn as_up(
        &mut self,
    ) -> Option<(InstanceUpView<'_>, &mut Interfaces)> {
        let state = self.state.as_mut()?;
        let instance = InstanceUpView {
            name: &self.name,
            system: &self.system,
            config: &self.config,
            state,
            tx: &self.tx,
            shared: &self.shared,
        };
        Some((instance, &mut self.interfaces))
    }
}

impl ProtocolInstance for Instance {
    const PROTOCOL: Protocol = Protocol::IGMP;

    type ProtocolInputMsg = ProtocolInputMsg;
    type ProtocolOutputMsg = ProtocolOutputMsg;
    type ProtocolInputChannelsTx = ProtocolInputChannelsTx;
    type ProtocolInputChannelsRx = ProtocolInputChannelsRx;

    fn new(
        name: String,
        shared: InstanceShared,
        tx: InstanceChannelsTx<Instance>,
    ) -> Instance {
        Instance {
            name,
            system: Default::default(),
            config: Default::default(),
            state: Default::default(),
            interfaces: Default::default(),
            tx,
            shared,
        }
    }

    fn init(&mut self) {
        // Create Rx socket.
        let socket_rx = network::socket_rx()
            .map_err(IoError::SocketError)
            .and_then(|socket| {
                AsyncFd::new(socket).map_err(IoError::SocketError)
            })
            .map(Arc::new)
            .expect("failed to create Rx socket");

        // Start network Rx task.
        let net = InstanceNet::new(socket_rx, self);

        // Store instance initial state.
        self.state = Some(InstanceState {
            net,
            statistics: Default::default(),
        });
    }

    fn shutdown(self) {
        // TODO: stop IGMP on all interfaces.

        // TODO: cleanup the running mcast handle task.
    }

    fn process_ibus_msg(&mut self, msg: IbusMsg) {
        if let Err(error) = process_ibus_msg(self, msg) {
            error.log();
        }
    }

    fn process_protocol_msg(&mut self, msg: ProtocolInputMsg) {
        if let Err(error) = process_protocol_msg(self, msg) {
            error.log();
        }
    }

    fn protocol_input_channels()
    -> (ProtocolInputChannelsTx, ProtocolInputChannelsRx) {
        let (net_packet_rxp, net_packet_rxc) = mpsc::channel(4);

        let tx = ProtocolInputChannelsTx {
            net_packet_rx: net_packet_rxp,
        };
        let rx = ProtocolInputChannelsRx {
            net_packet_rx: net_packet_rxc,
        };

        (tx, rx)
    }

    #[cfg(feature = "testing")]
    fn test_dir() -> String {
        format!("{}/tests/conformance", env!("CARGO_MANIFEST_DIR"),)
    }
}

// ===== impl InstanceNet =====

impl InstanceNet {
    pub(crate) fn new(
        socket_rx: Arc<AsyncFd<Socket>>,
        instance: &Instance,
    ) -> Self {
        let net_rx_task = tasks::net_rx(
            socket_rx.clone(),
            &instance.tx.protocol_input.net_packet_rx,
        );

        InstanceNet {
            socket_rx,
            _net_rx_task: net_rx_task,
        }
    }
}

// ===== impl ProtocolInputChannelsRx =====

impl MessageReceiver<ProtocolInputMsg> for ProtocolInputChannelsRx {
    async fn recv(&mut self) -> Option<ProtocolInputMsg> {
        tokio::select! {
            biased;
            msg = self.net_packet_rx.recv() => {
                msg.map(ProtocolInputMsg::NetRxPacket)
            }
        }
    }
}

// ===== helper functions =====

fn process_ibus_msg(
    instance: &mut Instance,
    msg: IbusMsg,
) -> Result<(), Error> {
    Debug::IbusRx(&msg).log();

    match msg {
        // Interface update notification.
        IbusMsg::InterfaceUpd(msg) => {
            ibus::rx::process_iface_update(instance, msg)?;
        }
        // Ignore other events.
        _ => {}
    }

    Ok(())
}

fn process_protocol_msg(
    instance: &mut Instance,
    msg: ProtocolInputMsg,
) -> Result<(), Error> {
    match msg {
        // Received network packet.
        ProtocolInputMsg::NetRxPacket(msg) => {
            events::process_packet(instance, msg.ifindex, msg.src, msg.packet)?;
        }
    }

    Ok(())
}
