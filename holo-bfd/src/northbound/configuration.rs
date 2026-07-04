//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};

use holo_northbound::configuration::{Provider, YangConfigOps};
use holo_northbound::error::ApplyError;
use holo_utils::bfd::{SessionKey, State};
use holo_utils::socket::TTL_MAX;

use crate::master::Master;
use crate::network;
use crate::northbound::yang_gen::bfd;
use crate::northbound::yang_gen::config::{self, ConfigChange, IpMhSessionGroupChange, IpMhSessionGroupEntryChange, IpShSessionChange, IpShSessionEntryChange};
use crate::packet::DiagnosticCode;
use crate::session::SessionIndex;

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    SessionDeleteCheck(SessionIndex),
    AdminDownChange(SessionIndex),
    StartPollSequence(SessionIndex),
    UpdateRxSockets,
    UpdateTxSocket(SessionIndex),
    UpdateTxInterval(SessionIndex),
}

// ===== configuration structs =====

#[derive(Debug)]
pub struct SessionCfg {
    // Common parameters.
    pub local_multiplier: u8,
    pub min_tx: u32,
    pub min_rx: u32,
    pub admin_down: bool,
    // IP single-hop parameters.
    pub src: Option<IpAddr>,
    // IP multihop parameters.
    pub tx_ttl: Option<u8>,
    pub rx_ttl: Option<u8>,
}

// ===== helper functions =====

fn apply_master(master: &mut Master, change: ConfigChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        ConfigChange::IpShSession(keys, change) => {
            apply_ip_sh_session(master, keys.interface, keys.dest_addr, change, event_queue)?;
        }
        ConfigChange::IpMhSessionGroup(keys, change) => {
            apply_ip_mh_session_group(master, keys.source_addr, keys.dest_addr, change, event_queue)?;
        }
        ConfigChange::IpShInterfaces(_keys, _change) => {
            // Nothing to do for now.
        }
    }

    Ok(())
}

fn apply_ip_sh_session(master: &mut Master, ifname: String, dst: IpAddr, change: IpShSessionChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    let sess_key = SessionKey::new_ip_single_hop(ifname.clone(), dst);

    match change {
        IpShSessionChange::Create => {
            // Get existing session or create a new one.
            let (sess_idx, sess) = master.sessions.insert(sess_key);
            sess.config_enabled = true;

            // Single-hop sessions can only be active as long as their
            // associated interface is present.
            if let Some(iface) = master.interfaces.get(&ifname) {
                master.sessions.update_ifindex(sess_idx, iface.ifindex);
            }

            event_queue.insert(Event::UpdateTxSocket(sess_idx));
            event_queue.insert(Event::UpdateTxInterval(sess_idx));
            event_queue.insert(Event::UpdateRxSockets);
        }
        IpShSessionChange::Delete => {
            let (sess_idx, sess) = master.sessions.get_mut_by_key(&sess_key).ok_or(ApplyError::EntryNotFound)?;
            sess.config_enabled = false;

            event_queue.insert(Event::SessionDeleteCheck(sess_idx));
            event_queue.insert(Event::UpdateRxSockets);
        }
        IpShSessionChange::Entry(change) => {
            let (sess_idx, sess) = master.sessions.get_mut_by_key(&sess_key).ok_or(ApplyError::EntryNotFound)?;
            match change {
                IpShSessionEntryChange::SourceAddr(src) => {
                    sess.config.src = src;
                    event_queue.insert(Event::UpdateTxSocket(sess_idx));
                    event_queue.insert(Event::UpdateTxInterval(sess_idx));
                }
                IpShSessionEntryChange::LocalMultiplier(local_multiplier) => {
                    sess.config.local_multiplier = local_multiplier;
                    // NOTE: the use of a Poll Sequence isn't necessary for
                    // this change.
                }
                IpShSessionEntryChange::DesiredMinTxInterval(min_tx) => {
                    if let Some(min_tx) = min_tx {
                        sess.config.min_tx = min_tx;
                        event_queue.insert(Event::StartPollSequence(sess_idx));
                        event_queue.insert(Event::UpdateTxInterval(sess_idx));
                    }
                }
                IpShSessionEntryChange::RequiredMinRxInterval(min_rx) => {
                    if let Some(min_rx) = min_rx {
                        sess.config.min_rx = min_rx;
                        event_queue.insert(Event::StartPollSequence(sess_idx));
                        event_queue.insert(Event::UpdateTxInterval(sess_idx));
                    }
                }
                IpShSessionEntryChange::MinInterval(min_interval) => {
                    if let Some(min_interval) = min_interval {
                        sess.config.min_tx = min_interval;
                        sess.config.min_rx = min_interval;
                        event_queue.insert(Event::StartPollSequence(sess_idx));
                        event_queue.insert(Event::UpdateTxInterval(sess_idx));
                    }
                }
                IpShSessionEntryChange::AdminDown(admin_down) => {
                    sess.config.admin_down = admin_down;
                    event_queue.insert(Event::AdminDownChange(sess_idx));
                }
            }
        }
    }

    Ok(())
}

fn apply_ip_mh_session_group(master: &mut Master, src: IpAddr, dst: IpAddr, change: IpMhSessionGroupChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    let sess_key = SessionKey::new_ip_multihop(src, dst);

    match change {
        IpMhSessionGroupChange::Create => {
            // Get existing session or create a new one.
            let (sess_idx, sess) = master.sessions.insert(sess_key);
            sess.config.tx_ttl = Some(TTL_MAX);
            sess.config.rx_ttl = Some(TTL_MAX);
            sess.config_enabled = true;

            // Initialize session's socket address.
            sess.state.sockaddr = Some(SocketAddr::new(dst, network::PORT_DST_MULTIHOP));

            event_queue.insert(Event::UpdateRxSockets);
            event_queue.insert(Event::UpdateTxSocket(sess_idx));
            event_queue.insert(Event::UpdateTxInterval(sess_idx));
        }
        IpMhSessionGroupChange::Delete => {
            let (sess_idx, sess) = master.sessions.get_mut_by_key(&sess_key).ok_or(ApplyError::EntryNotFound)?;
            sess.config_enabled = false;

            event_queue.insert(Event::SessionDeleteCheck(sess_idx));
            event_queue.insert(Event::UpdateRxSockets);
        }
        IpMhSessionGroupChange::Entry(change) => {
            let (sess_idx, sess) = master.sessions.get_mut_by_key(&sess_key).ok_or(ApplyError::EntryNotFound)?;
            match change {
                IpMhSessionGroupEntryChange::LocalMultiplier(local_multiplier) => {
                    sess.config.local_multiplier = local_multiplier;
                    // NOTE: the use of a Poll Sequence isn't necessary for
                    // this change.
                }
                IpMhSessionGroupEntryChange::DesiredMinTxInterval(min_tx) => {
                    if let Some(min_tx) = min_tx {
                        sess.config.min_tx = min_tx;
                        event_queue.insert(Event::StartPollSequence(sess_idx));
                        event_queue.insert(Event::UpdateTxInterval(sess_idx));
                    }
                }
                IpMhSessionGroupEntryChange::RequiredMinRxInterval(min_rx) => {
                    if let Some(min_rx) = min_rx {
                        sess.config.min_rx = min_rx;
                        event_queue.insert(Event::StartPollSequence(sess_idx));
                        event_queue.insert(Event::UpdateTxInterval(sess_idx));
                    }
                }
                IpMhSessionGroupEntryChange::MinInterval(min_interval) => {
                    if let Some(min_interval) = min_interval {
                        sess.config.min_tx = min_interval;
                        sess.config.min_rx = min_interval;
                        event_queue.insert(Event::StartPollSequence(sess_idx));
                        event_queue.insert(Event::UpdateTxInterval(sess_idx));
                    }
                }
                IpMhSessionGroupEntryChange::AdminDown(admin_down) => {
                    sess.config.admin_down = admin_down;
                    event_queue.insert(Event::AdminDownChange(sess_idx));
                }
                IpMhSessionGroupEntryChange::TxTtl(ttl) => {
                    sess.config.tx_ttl = Some(ttl);
                    event_queue.insert(Event::UpdateTxSocket(sess_idx));
                    event_queue.insert(Event::UpdateTxInterval(sess_idx));
                }
                IpMhSessionGroupEntryChange::RxTtl(ttl) => {
                    sess.config.rx_ttl = Some(ttl);
                }
            }
        }
    }

    Ok(())
}

fn process_event(master: &mut Master, event: Event) {
    match event {
        Event::SessionDeleteCheck(sess_idx) => {
            master.sessions.delete_check(sess_idx);
        }
        Event::AdminDownChange(sess_idx) => {
            let sess = &mut master.sessions[sess_idx];
            let (state, diag) = match sess.config.admin_down {
                true => (State::AdminDown, DiagnosticCode::AdminDown),
                false => (State::Down, DiagnosticCode::Nothing),
            };
            sess.state_update(state, diag, &master.tx);

            // Should we stop sending packets after one Detection Time?
        }
        Event::StartPollSequence(sess_idx) => {
            let sess = &mut master.sessions[sess_idx];
            sess.poll_sequence_start();
        }
        Event::UpdateRxSockets => {
            // Start or stop UDP Rx tasks if necessary.
            master.update_udp_rx_tasks();
        }
        Event::UpdateTxSocket(sess_idx) => {
            let sess = &mut master.sessions[sess_idx];
            sess.update_socket_tx();
        }
        Event::UpdateTxInterval(sess_idx) => {
            let sess = &mut master.sessions[sess_idx];
            sess.update_tx_interval();
        }
    }
}

// ===== impl Master =====

impl Provider for Master {
    type Event = Event;
    type Resource = Resource;
    type Change = ConfigChange;

    const YANG_OPS_CONFIG: YangConfigOps<ConfigChange> = config::YANG_OPS_CONFIG;

    fn apply(&mut self, change: ConfigChange, _resource: &mut Option<Resource>, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
        apply_master(self, change, event_queue)
    }

    fn process_event(&mut self, event: Event) {
        process_event(self, event);
    }
}

// ===== configuration defaults =====

impl Default for SessionCfg {
    fn default() -> SessionCfg {
        let local_multiplier = bfd::ip_sh::sessions::session::local_multiplier::DFLT;
        let min_tx = bfd::ip_sh::sessions::session::desired_min_tx_interval::DFLT;
        let min_rx = bfd::ip_sh::sessions::session::required_min_rx_interval::DFLT;
        let admin_down = bfd::ip_sh::sessions::session::admin_down::DFLT;

        SessionCfg {
            local_multiplier,
            min_tx,
            min_rx,
            admin_down,
            src: None,
            tx_ttl: None,
            rx_ttl: None,
        }
    }
}
