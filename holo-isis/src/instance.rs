//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::Instant;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use holo_protocol::{
    InstanceChannelsTx, InstanceShared, MessageReceiver, ProtocolInstance,
};
use holo_utils::ibus::IbusMsg;
use holo_utils::protocol::Protocol;
use holo_utils::task::TimeoutTask;
use holo_utils::{Receiver, Sender, UnboundedReceiver, UnboundedSender};
use tokio::sync::mpsc;

use crate::adjacency::Adjacency;
use crate::collections::{Arena, Interfaces, Lsdb, LspEntryId};
use crate::debug::{
    Debug, InstanceInactiveReason, InterfaceInactiveReason, LspPurgeReason,
};
use crate::error::Error;
use crate::interface::CircuitIdAllocator;
use crate::lsdb::{LspEntry, LspLogEntry};
use crate::northbound::configuration::InstanceCfg;
use crate::packet::{LevelNumber, LevelType, Levels};
use crate::tasks::messages::input::{
    AdjHoldTimerMsg, DisElectionMsg, LspDeleteMsg, LspOriginateMsg,
    LspPurgeMsg, LspRefreshMsg, NetRxPduMsg, SendCsnpMsg, SendPsnpMsg,
};
use crate::tasks::messages::{ProtocolInputMsg, ProtocolOutputMsg};
use crate::{events, lsdb, southbound, tasks};

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
    // Instance arenas.
    pub arenas: InstanceArenas,
    // Instance Tx channels.
    pub tx: InstanceChannelsTx<Instance>,
    // Shared data.
    pub shared: InstanceShared,
}

#[derive(Debug, Default)]
pub struct InstanceSys {
    // System Router ID.
    pub router_id: Option<Ipv4Addr>,
}

#[derive(Debug)]
pub struct InstanceState {
    // Circuit ID allocator.
    pub circuit_id_allocator: CircuitIdAllocator,
    // Link State Database.
    pub lsdb: Levels<Lsdb>,
    // LSP origination data.
    pub lsp_orig_last: Option<Instant>,
    pub lsp_orig_backoff: Option<TimeoutTask>,
    pub lsp_orig_pending: Option<LevelType>,
    // Event counters.
    pub counters: Levels<InstanceCounters>,
    pub discontinuity_time: DateTime<Utc>,
    // Log of LSP updates.
    pub lsp_log: VecDeque<LspLogEntry>,
    pub lsp_log_next_id: u32,
}

#[derive(Debug, Default)]
pub struct InstanceCounters {
    pub corrupted_lsps: u32,
    pub auth_type_fails: u32,
    pub auth_fails: u32,
    pub database_overload: u32,
    pub own_lsp_purge: u32,
    pub manual_addr_drop_from_area: u32,
    pub max_sequence: u32,
    pub seqno_skipped: u32,
    pub id_len_mismatch: u32,
    pub partition_changes: u32,
    pub lsp_errors: u32,
    pub spf_runs: u32,
}

#[derive(Debug, Default)]
pub struct InstanceArenas {
    pub interfaces: Interfaces,
    pub adjacencies: Arena<Adjacency>,
    pub lsp_entries: Arena<LspEntry>,
}

#[derive(Clone, Debug)]
pub struct ProtocolInputChannelsTx {
    // PDU Rx event.
    pub net_pdu_rx: Sender<NetRxPduMsg>,
    // Adjacency hold timer event.
    pub adj_holdtimer: Sender<AdjHoldTimerMsg>,
    // Request to run DIS election.
    pub dis_election: UnboundedSender<DisElectionMsg>,
    // Request to send PSNP(s).
    pub send_psnp: UnboundedSender<SendPsnpMsg>,
    // Request to send CSNP(s).
    pub send_csnp: UnboundedSender<SendCsnpMsg>,
    // LSP originate event.
    pub lsp_originate: UnboundedSender<LspOriginateMsg>,
    // LSP purge event.
    pub lsp_purge: UnboundedSender<LspPurgeMsg>,
    // LSP delete event.
    pub lsp_delete: UnboundedSender<LspDeleteMsg>,
    // LSP refresh event.
    pub lsp_refresh: UnboundedSender<LspRefreshMsg>,
}

#[derive(Debug)]
pub struct ProtocolInputChannelsRx {
    // PDU Rx event.
    pub net_pdu_rx: Receiver<NetRxPduMsg>,
    // Adjacency hold timer event.
    pub adj_holdtimer: Receiver<AdjHoldTimerMsg>,
    // Request to run DIS election.
    pub dis_election: UnboundedReceiver<DisElectionMsg>,
    // Request to send PSNP(s).
    pub send_psnp: UnboundedReceiver<SendPsnpMsg>,
    // Request to send CSNP(s).
    pub send_csnp: UnboundedReceiver<SendCsnpMsg>,
    // LSP originate event.
    pub lsp_originate: UnboundedReceiver<LspOriginateMsg>,
    // LSP purge event.
    pub lsp_purge: UnboundedReceiver<LspPurgeMsg>,
    // LSP delete event.
    pub lsp_delete: UnboundedReceiver<LspDeleteMsg>,
    // LSP refresh event.
    pub lsp_refresh: UnboundedReceiver<LspRefreshMsg>,
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
    // Checks if the instance needs to be started or stopped in response to a
    // northbound or southbound event.
    pub(crate) fn update(&mut self) {
        match self.is_ready() {
            Ok(()) if !self.is_active() => {
                self.start();
            }
            Err(reason) if self.is_active() => {
                self.stop(reason);
            }
            _ => (),
        }
    }

    // Starts the IS-IS instance.
    fn start(&mut self) {
        Debug::InstanceStart.log();

        // Create instance initial state.
        let state = InstanceState::new(&self.tx);
        self.state = Some(state);

        // Start interfaces.
        for iface in self.arenas.interfaces.iter() {
            iface.query_southbound(&self.tx.ibus);
        }

        // Schedule initial LSP origination.
        let (mut instance, _) = self.as_up().unwrap();
        instance.schedule_lsp_origination(LevelType::All);
    }

    // Stops the IS-IS instance.
    fn stop(&mut self, reason: InstanceInactiveReason) {
        Debug::InstanceStop(reason).log();

        // Stop interfaces.
        let (mut instance, arenas) = self.as_up().unwrap();
        let reason = InterfaceInactiveReason::InstanceDown;
        for iface in arenas
            .interfaces
            .iter_mut()
            .filter(|iface| iface.state.active)
        {
            iface.stop(&mut instance, &mut arenas.adjacencies, reason);
        }

        // Clear instance state.
        self.state = None;
    }

    // Resets the IS-IS instance.
    pub(crate) fn reset(&mut self) {
        if self.is_active() {
            self.stop(InstanceInactiveReason::Resetting);
            self.update();
        }
    }

    // Returns whether the IS-IS instance is operational.
    pub(crate) fn is_active(&self) -> bool {
        self.state.is_some()
    }

    // Returns whether the instance is ready for IS-IS operation.
    fn is_ready(&self) -> Result<(), InstanceInactiveReason> {
        if !self.config.enabled || self.config.system_id.is_none() {
            return Err(InstanceInactiveReason::AdminDown);
        }

        Ok(())
    }

    // Returns a view struct for the instance if it's operational.
    pub(crate) fn as_up(
        &mut self,
    ) -> Option<(InstanceUpView<'_>, &mut InstanceArenas)> {
        if let Some(state) = &mut self.state {
            let instance = InstanceUpView {
                name: &self.name,
                system: &self.system,
                config: &self.config,
                state,
                tx: &self.tx,
                shared: &self.shared,
            };
            Some((instance, &mut self.arenas))
        } else {
            None
        }
    }
}

#[async_trait]
impl ProtocolInstance for Instance {
    const PROTOCOL: Protocol = Protocol::ISIS;

    type ProtocolInputMsg = ProtocolInputMsg;
    type ProtocolOutputMsg = ProtocolOutputMsg;
    type ProtocolInputChannelsTx = ProtocolInputChannelsTx;
    type ProtocolInputChannelsRx = ProtocolInputChannelsRx;

    async fn new(
        name: String,
        shared: InstanceShared,
        tx: InstanceChannelsTx<Instance>,
    ) -> Instance {
        Debug::InstanceCreate.log();

        Instance {
            name,
            system: Default::default(),
            config: Default::default(),
            state: None,
            arenas: Default::default(),
            tx,
            shared,
        }
    }

    async fn init(&mut self) {
        // Request information about the system Router ID.
        southbound::tx::router_id_query(&self.tx.ibus);
    }

    async fn shutdown(mut self) {
        // Ensure instance is disabled before exiting.
        self.stop(InstanceInactiveReason::AdminDown);
        Debug::InstanceDelete.log();
    }

    async fn process_ibus_msg(&mut self, msg: IbusMsg) {
        if let Err(error) = process_ibus_msg(self, msg).await {
            error.log(&self.arenas);
        }
    }

    fn process_protocol_msg(&mut self, msg: ProtocolInputMsg) {
        // Ignore event if the instance isn't active.
        let Some((mut instance, arenas)) = self.as_up() else {
            return;
        };

        if let Err(error) = process_protocol_msg(&mut instance, arenas, msg) {
            error.log(arenas);
        }
    }

    fn protocol_input_channels(
    ) -> (ProtocolInputChannelsTx, ProtocolInputChannelsRx) {
        let (net_pdu_rxp, net_pdu_rxc) = mpsc::channel(4);
        let (adj_holdtimerp, adj_holdtimerc) = mpsc::channel(4);
        let (dis_electionp, dis_electionc) = mpsc::unbounded_channel();
        let (send_psnpp, send_psnpc) = mpsc::unbounded_channel();
        let (send_csnpp, send_csnpc) = mpsc::unbounded_channel();
        let (lsp_originatep, lsp_originatec) = mpsc::unbounded_channel();
        let (lsp_purgep, lsp_purgec) = mpsc::unbounded_channel();
        let (lsp_deletep, lsp_deletec) = mpsc::unbounded_channel();
        let (lsp_refreshp, lsp_refreshc) = mpsc::unbounded_channel();

        let tx = ProtocolInputChannelsTx {
            net_pdu_rx: net_pdu_rxp,
            adj_holdtimer: adj_holdtimerp,
            dis_election: dis_electionp,
            send_psnp: send_psnpp,
            send_csnp: send_csnpp,
            lsp_originate: lsp_originatep,
            lsp_purge: lsp_purgep,
            lsp_delete: lsp_deletep,
            lsp_refresh: lsp_refreshp,
        };
        let rx = ProtocolInputChannelsRx {
            net_pdu_rx: net_pdu_rxc,
            adj_holdtimer: adj_holdtimerc,
            dis_election: dis_electionc,
            send_psnp: send_psnpc,
            send_csnp: send_csnpc,
            lsp_originate: lsp_originatec,
            lsp_purge: lsp_purgec,
            lsp_delete: lsp_deletec,
            lsp_refresh: lsp_refreshc,
        };

        (tx, rx)
    }

    #[cfg(feature = "testing")]
    fn test_dir() -> String {
        format!("{}/tests/conformance", env!("CARGO_MANIFEST_DIR"),)
    }
}

// ===== impl InstanceState =====

impl InstanceState {
    fn new(_instance_tx: &InstanceChannelsTx<Instance>) -> InstanceState {
        InstanceState {
            circuit_id_allocator: Default::default(),
            lsdb: Default::default(),
            lsp_orig_last: None,
            lsp_orig_backoff: None,
            lsp_orig_pending: None,
            counters: Default::default(),
            discontinuity_time: Utc::now(),
            lsp_log: Default::default(),
            lsp_log_next_id: 0,
        }
    }
}

// ===== impl ProtocolInputChannelsTx =====

impl ProtocolInputChannelsTx {
    pub(crate) fn lsp_purge(
        &self,
        level: LevelNumber,
        lse_id: LspEntryId,
        reason: LspPurgeReason,
    ) {
        let msg = LspPurgeMsg {
            level,
            lse_key: lse_id.into(),
            reason,
        };
        let _ = self.lsp_purge.send(msg);
    }

    pub(crate) fn lsp_refresh(&self, level: LevelNumber, lse_id: LspEntryId) {
        let msg = LspRefreshMsg {
            level,
            lse_key: lse_id.into(),
        };
        let _ = self.lsp_refresh.send(msg);
    }
}

// ===== impl ProtocolInputChannelsRx =====

#[async_trait]
impl MessageReceiver<ProtocolInputMsg> for ProtocolInputChannelsRx {
    async fn recv(&mut self) -> Option<ProtocolInputMsg> {
        tokio::select! {
            biased;
            msg = self.net_pdu_rx.recv() => {
                msg.map(ProtocolInputMsg::NetRxPdu)
            }
            msg = self.adj_holdtimer.recv() => {
                msg.map(ProtocolInputMsg::AdjHoldTimer)
            }
            msg = self.dis_election.recv() => {
                msg.map(ProtocolInputMsg::DisElection)
            }
            msg = self.send_psnp.recv() => {
                msg.map(ProtocolInputMsg::SendPsnp)
            }
            msg = self.send_csnp.recv() => {
                msg.map(ProtocolInputMsg::SendCsnp)
            }
            msg = self.lsp_originate.recv() => {
                msg.map(ProtocolInputMsg::LspOriginate)
            }
            msg = self.lsp_purge.recv() => {
                msg.map(ProtocolInputMsg::LspPurge)
            }
            msg = self.lsp_delete.recv() => {
                msg.map(ProtocolInputMsg::LspDelete)
            }
            msg = self.lsp_refresh.recv() => {
                msg.map(ProtocolInputMsg::LspRefresh)
            }
        }
    }
}

// ===== impl InstanceUpView =====

impl InstanceUpView<'_> {
    pub(crate) fn schedule_lsp_origination(
        &mut self,
        level_type: impl Into<LevelType>,
    ) {
        let level_type = level_type.into();

        // Update pending LSP origination with the union of the current and
        // new level.
        self.state.lsp_orig_pending = match self.state.lsp_orig_pending {
            Some(pending_level) => Some(level_type.union(pending_level)),
            None => Some(level_type),
        };

        #[cfg(not(feature = "deterministic"))]
        {
            // If LSP origination is currently in backoff, do nothing.
            if self.state.lsp_orig_backoff.is_some() {
                return;
            }

            // If the minimum interval since the last LSP origination hasn't
            // passed, initiate a backoff timer and return.
            if let Some(last) = self.state.lsp_orig_last
                && last.elapsed().as_secs() < lsdb::LSP_MIN_GEN_INTERVAL
            {
                let task = tasks::lsp_originate_timer(
                    &self.tx.protocol_input.lsp_originate,
                );
                self.state.lsp_orig_backoff = Some(task);
                return;
            }
        }

        // Trigger LSP origination.
        let _ = self
            .tx
            .protocol_input
            .lsp_originate
            .send(LspOriginateMsg {});
    }
}

// ===== helper functions =====

async fn process_ibus_msg(
    instance: &mut Instance,
    msg: IbusMsg,
) -> Result<(), Error> {
    match msg {
        // Router ID update notification.
        IbusMsg::RouterIdUpdate(router_id) => {
            southbound::rx::process_router_id_update(instance, router_id).await;
        }
        // Interface update notification.
        IbusMsg::InterfaceUpd(msg) => {
            southbound::rx::process_iface_update(instance, msg)?;
        }
        // Interface address addition notification.
        IbusMsg::InterfaceAddressAdd(msg) => {
            southbound::rx::process_addr_add(instance, msg);
        }
        // Interface address deletion notification.
        IbusMsg::InterfaceAddressDel(msg) => {
            southbound::rx::process_addr_del(instance, msg);
        }
        // Ignore other events.
        _ => {}
    }

    Ok(())
}

fn process_protocol_msg(
    instance: &mut InstanceUpView<'_>,
    arenas: &mut InstanceArenas,
    msg: ProtocolInputMsg,
) -> Result<(), Error> {
    match msg {
        // Received network PDU.
        ProtocolInputMsg::NetRxPdu(msg) => {
            events::process_pdu(
                instance,
                arenas,
                msg.iface_key,
                msg.src,
                msg.bytes,
                msg.pdu,
            )?;
        }
        // Adjacency hold timer event.
        ProtocolInputMsg::AdjHoldTimer(msg) => match msg {
            AdjHoldTimerMsg::Broadcast {
                iface_key,
                adj_key,
                level,
            } => {
                events::process_lan_adj_holdtimer_expiry(
                    instance, arenas, iface_key, adj_key, level,
                )?;
            }
            AdjHoldTimerMsg::PointToPoint { iface_key } => {
                events::process_p2p_adj_holdtimer_expiry(
                    instance, arenas, iface_key,
                )?;
            }
        },
        // Request to run DIS election.
        ProtocolInputMsg::DisElection(msg) => {
            events::process_dis_election(
                instance,
                arenas,
                msg.iface_key,
                msg.level,
            )?;
        }
        // Request to run send PSNP(s).
        ProtocolInputMsg::SendPsnp(msg) => {
            events::process_send_psnp(
                instance,
                arenas,
                msg.iface_key,
                msg.level,
            )?;
        }
        // Request to run send CSNP(s).
        ProtocolInputMsg::SendCsnp(msg) => {
            events::process_send_csnp(
                instance,
                arenas,
                msg.iface_key,
                msg.level,
            )?;
        }
        // LSP origination event.
        ProtocolInputMsg::LspOriginate(_msg) => {
            events::process_lsp_originate(instance, arenas)?;
        }
        // LSP purge event.
        ProtocolInputMsg::LspPurge(msg) => {
            events::process_lsp_purge(
                instance,
                arenas,
                msg.level,
                msg.lse_key,
                msg.reason,
            )?;
        }
        // LSP delete event.
        ProtocolInputMsg::LspDelete(msg) => {
            events::process_lsp_delete(
                instance,
                arenas,
                msg.level,
                msg.lse_key,
            )?;
        }
        // LSP refresh event.
        ProtocolInputMsg::LspRefresh(msg) => {
            events::process_lsp_refresh(
                instance,
                arenas,
                msg.level,
                msg.lse_key,
            )?;
        }
    }

    Ok(())
}