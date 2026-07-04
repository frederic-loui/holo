//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use holo_northbound::configuration::{ConfigOp, Provider, YangConfigOps};
use holo_northbound::error::ApplyError;
use holo_utils::crypto::CryptoAlgo;
use holo_utils::keychain::{Key, Keychain, KeychainKey};

use crate::Master;
use crate::northbound::yang_gen::config::{self, ConfigChange, KeyChainChange, KeyChainEntryChange, KeyChainKeyChange, KeyChainKeyEntryChange};

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    KeychainChange(String),
    KeychainDelete(String),
}

// ===== helper functions =====

fn apply_master(master: &mut Master, change: ConfigChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    let ConfigChange::KeyChain(keys, change) = change;
    apply_key_chain(master, keys.name, change, event_queue)?;

    Ok(())
}

fn apply_key_chain(master: &mut Master, name: String, change: KeyChainChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        KeyChainChange::Create => {
            let keychain = Keychain::new(name.clone());
            master.keychains.insert(name, keychain);
        }
        KeyChainChange::Delete => {
            master.keychains.remove(&name);
            event_queue.insert(Event::KeychainDelete(name));
        }
        KeyChainChange::Entry(change) => {
            let keychain = master.keychains.get_mut(&name).ok_or(ApplyError::EntryNotFound)?;
            match change {
                KeyChainEntryChange::Description(_description) => {
                    // Nothing to do.
                }
                KeyChainEntryChange::Key(keys, change) => {
                    apply_key_chain_key(keychain, keys.key_id, change)?;
                    event_queue.insert(Event::KeychainChange(name));
                }
            }
        }
    }

    Ok(())
}

fn apply_key_chain_key(keychain: &mut Keychain, key_id: u64, change: KeyChainKeyChange) -> Result<(), ApplyError> {
    match change {
        KeyChainKeyChange::Create => {
            // The mandatory crypto-algorithm leaf is applied as a separate
            // change within the same commit, overwriting the placeholder
            // algorithm before any event fires.
            let key = KeychainKey::new(Key::new(key_id, CryptoAlgo::ClearText, Default::default()));
            keychain.keys.insert(key_id, key);
        }
        KeyChainKeyChange::Delete => {
            keychain.keys.remove(&key_id);
        }
        KeyChainKeyChange::Entry(change) => {
            let key = keychain.keys.get_mut(&key_id).ok_or(ApplyError::EntryNotFound)?;
            match change {
                KeyChainKeyEntryChange::LifetimeSendAcceptLifetimeAlways(op) => {
                    if op == ConfigOp::Create {
                        key.send_lifetime.start = None;
                        key.send_lifetime.end = None;
                        key.accept_lifetime.start = None;
                        key.accept_lifetime.end = None;
                    }
                }
                KeyChainKeyEntryChange::LifetimeSendAcceptLifetimeStartDateTime(start) => {
                    let start = start.map(|start| start.fixed_offset());
                    key.send_lifetime.start = start;
                    key.accept_lifetime.start = start;
                }
                KeyChainKeyEntryChange::LifetimeSendAcceptLifetimeNoEndTime(op) => {
                    if op == ConfigOp::Create {
                        key.send_lifetime.end = None;
                        key.accept_lifetime.end = None;
                    }
                }
                KeyChainKeyEntryChange::LifetimeSendAcceptLifetimeDuration(seconds) => {
                    if let Some(seconds) = seconds
                        && let Ok(duration) = chrono::Duration::from_std(Duration::from_secs(seconds as u64))
                    {
                        if let Some(start) = key.send_lifetime.start {
                            key.send_lifetime.end = Some(start + duration);
                        }
                        if let Some(start) = key.accept_lifetime.start {
                            key.accept_lifetime.end = Some(start + duration);
                        }
                    }
                }
                KeyChainKeyEntryChange::LifetimeSendAcceptLifetimeEndDateTime(end) => {
                    let end = end.map(|end| end.fixed_offset());
                    key.send_lifetime.end = end;
                    key.accept_lifetime.end = end;
                }
                KeyChainKeyEntryChange::LifetimeSendLifetimeAlways(op) => {
                    if op == ConfigOp::Create {
                        key.send_lifetime.start = None;
                        key.send_lifetime.end = None;
                    }
                }
                KeyChainKeyEntryChange::LifetimeSendLifetimeStartDateTime(start) => {
                    key.send_lifetime.start = start.map(|start| start.fixed_offset());
                }
                KeyChainKeyEntryChange::LifetimeSendLifetimeNoEndTime(op) => {
                    if op == ConfigOp::Create {
                        key.send_lifetime.end = None;
                    }
                }
                KeyChainKeyEntryChange::LifetimeSendLifetimeDuration(seconds) => {
                    if let Some(seconds) = seconds
                        && let Ok(duration) = chrono::Duration::from_std(Duration::from_secs(seconds as u64))
                        && let Some(start) = key.send_lifetime.start
                    {
                        key.send_lifetime.end = Some(start + duration);
                    }
                }
                KeyChainKeyEntryChange::LifetimeSendLifetimeEndDateTime(end) => {
                    key.send_lifetime.end = end.map(|end| end.fixed_offset());
                }
                KeyChainKeyEntryChange::LifetimeAcceptLifetimeAlways(op) => {
                    if op == ConfigOp::Create {
                        key.accept_lifetime.start = None;
                        key.accept_lifetime.end = None;
                    }
                }
                KeyChainKeyEntryChange::LifetimeAcceptLifetimeStartDateTime(start) => {
                    key.accept_lifetime.start = start.map(|start| start.fixed_offset());
                }
                KeyChainKeyEntryChange::LifetimeAcceptLifetimeNoEndTime(op) => {
                    if op == ConfigOp::Create {
                        key.accept_lifetime.end = None;
                    }
                }
                KeyChainKeyEntryChange::LifetimeAcceptLifetimeDuration(seconds) => {
                    if let Some(seconds) = seconds
                        && let Ok(duration) = chrono::Duration::from_std(Duration::from_secs(seconds as u64))
                        && let Some(start) = key.accept_lifetime.start
                    {
                        key.accept_lifetime.end = Some(start + duration);
                    }
                }
                KeyChainKeyEntryChange::LifetimeAcceptLifetimeEndDateTime(end) => {
                    key.accept_lifetime.end = end.map(|end| end.fixed_offset());
                }
                KeyChainKeyEntryChange::CryptoAlgorithm(algo) => {
                    key.data.algo = algo;
                }
                KeyChainKeyEntryChange::KeyStringKeystring(string) => {
                    key.data.string = match string {
                        Some(string) => string.into_bytes(),
                        None => Vec::new(),
                    };
                }
                KeyChainKeyEntryChange::KeyStringHexadecimalString(string) => {
                    key.data.string = match string {
                        Some(string) => string.0,
                        None => Vec::new(),
                    };
                }
            }
        }
    }

    Ok(())
}

fn process_event(master: &mut Master, event: Event) {
    match event {
        Event::KeychainChange(name) => {
            let Some(keychain) = master.keychains.get_mut(&name) else {
                return;
            };

            // Update timestamp of the most recent update.
            keychain.last_modified = Some(Utc::now());

            // Update maximum digest size.
            keychain.max_digest_size = keychain.keys.values().map(|key| key.data.algo.digest_size()).max().unwrap_or(0);

            // Create a reference-counted copy of the keychain to be shared among all
            // protocol instances.
            let keychain = Arc::new(keychain.clone());

            // Notify protocols that the keychain has been updated.
            master.ibus_tx.keychain_upd(keychain);
        }
        Event::KeychainDelete(name) => {
            // Notify protocols that the keychain has been deleted.
            master.ibus_tx.keychain_del(name);
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
