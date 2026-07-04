//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;

use holo_northbound::configuration::{Provider, YangConfigOps};
use holo_northbound::error::ApplyError;

use crate::northbound::yang_gen::config::{self, ConfigChange};
use crate::{Master, ibus};

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    HostnameChange,
}

// ===== configuration structs =====

#[derive(Debug, Default)]
pub struct SystemCfg {
    pub contact: Option<String>,
    pub hostname: Option<String>,
    pub location: Option<String>,
}

// ===== helper functions =====

fn apply_master(master: &mut Master, change: ConfigChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        ConfigChange::Contact(contact) => {
            master.config.contact = contact;
        }
        ConfigChange::Hostname(hostname) => {
            master.config.hostname = hostname;
            event_queue.insert(Event::HostnameChange);
        }
        ConfigChange::Location(location) => {
            master.config.location = location;
        }
    }

    Ok(())
}

fn process_event(master: &mut Master, event: Event) {
    match event {
        Event::HostnameChange => {
            for ibus_tx in master.hostname_subscriptions.values() {
                ibus::notify_hostname_update(ibus_tx, master.config.hostname.clone());
            }
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
