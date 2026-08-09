//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use holo_northbound::configuration::{Provider, ValidateFn, YangConfigOps};
use holo_northbound::error::{ApplyError, ValidationError};
use holo_utils::auth::User;
use holo_utils::yang::{DataNodeRefExt, DataTreeExt};
use yang5::data::DataTree;

use crate::northbound::yang_gen::config::{self, AuthenticationUserChange, AuthenticationUserEntryChange, ConfigChange};
use crate::northbound::yang_gen::system::authentication::user;
use crate::{Master, ibus};

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    HostnameChange,
    UsersChange,
}

// ===== configuration structs =====

#[derive(Debug, Default)]
pub struct SystemCfg {
    pub contact: Option<String>,
    pub hostname: Option<String>,
    pub location: Option<String>,
    pub users: BTreeMap<String, User>,
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
        ConfigChange::AuthenticationUser(keys, change) => {
            apply_user(master, keys.name, change, event_queue)?;
        }
    }

    Ok(())
}

fn apply_user(master: &mut Master, name: String, change: AuthenticationUserChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        AuthenticationUserChange::Create => {
            master.config.users.insert(name, User::default());
        }
        AuthenticationUserChange::Delete => {
            master.config.users.remove(&name);
        }
        AuthenticationUserChange::Entry(change) => {
            let user = master.config.users.get_mut(&name).ok_or(ApplyError::EntryNotFound)?;
            match change {
                AuthenticationUserEntryChange::Password(password) => {
                    user.password = password;
                }
            }
        }
    }
    event_queue.insert(Event::UsersChange);

    Ok(())
}

fn process_event(master: &mut Master, event: Event) {
    match event {
        Event::HostnameChange => {
            for ibus_tx in master.hostname_subscriptions.values() {
                ibus::notify_hostname_update(ibus_tx, master.config.hostname.clone());
            }
        }
        Event::UsersChange => {
            let users = Arc::new(master.config.users.clone());
            for ibus_tx in master.users_subscriptions.values() {
                ibus::notify_users_update(ibus_tx, users.clone());
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

    fn validation_fns() -> Vec<ValidateFn> {
        vec![validate]
    }

    fn apply(&mut self, change: ConfigChange, _resource: &mut Option<Resource>, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
        apply_master(self, change, event_queue)
    }

    fn process_event(&mut self, event: Event) {
        process_event(self, event);
    }
}

// ===== global functions =====

pub fn validate(config: &DataTree<'static>) -> Result<(), ValidationError> {
    // The crypt-hash-* features advertised for iana-crypt-hash are purely
    // informational, as nothing in that module is conditioned on them. The
    // leaf's pattern keeps accepting every form regardless of which features
    // are advertised, so the hashes the daemon can actually verify have to be
    // enforced here.
    for dnode in config.iter_path(user::password::PATH) {
        let password = dnode.get_string();
        if !password.starts_with("$5$") && !password.starts_with("$6$") {
            let message = "Password must be hashed with SHA-256 ($5$) or SHA-512 ($6$).";
            return Err(ValidationError::new(&dnode, message));
        }
    }

    Ok(())
}
