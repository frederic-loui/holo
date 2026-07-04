//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use holo_northbound::configuration::{ConfigOp, Provider, YangConfigOps};
use holo_northbound::error::ApplyError;

use crate::instance::Instance;
use crate::interface::Interface;
use crate::northbound::yang_gen::config::{self, ConfigChange, InterfaceChange, InterfaceEntryChange};
use crate::northbound::yang_gen::igmp;

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    InterfaceUpdate(String),
    InterfaceIbusSub(String),
}

// ===== configuration structs =====

#[derive(Debug)]
pub struct InstanceCfg {}

#[derive(Debug)]
pub struct InterfaceCfg {
    pub last_member_query_interval: u16,
    pub query_interval: u16,
    pub query_max_response_time: u16,
    pub robustness_variable: u8,
    pub enabled: bool,
    pub join_group: BTreeSet<Ipv4Addr>,
}

// ===== helper functions =====

fn apply_instance(instance: &mut Instance, change: ConfigChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        ConfigChange::Interface(keys, change) => {
            apply_interface(instance, keys.interface_name, change, event_queue)?;
        }
    }

    Ok(())
}

fn apply_interface(instance: &mut Instance, ifname: String, change: InterfaceChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        InterfaceChange::Create => {
            let iface = Interface::new(ifname.clone());
            instance.interfaces.insert(ifname.clone(), iface);

            event_queue.insert(Event::InterfaceUpdate(ifname.clone()));
            event_queue.insert(Event::InterfaceIbusSub(ifname));
        }
        InterfaceChange::Delete => {
            instance.interfaces.remove(&ifname);
        }
        InterfaceChange::Entry(change) => {
            let iface = instance.interfaces.get_mut(&ifname).ok_or(ApplyError::EntryNotFound)?;
            match change {
                InterfaceEntryChange::LastMemberQueryInterval(interval) => {
                    iface.config.last_member_query_interval = interval;
                }
                InterfaceEntryChange::QueryInterval(interval) => {
                    iface.config.query_interval = interval;
                }
                InterfaceEntryChange::QueryMaxResponseTime(time) => {
                    iface.config.query_max_response_time = time;
                }
                InterfaceEntryChange::RobustnessVariable(robustness_variable) => {
                    iface.config.robustness_variable = robustness_variable;
                }
                InterfaceEntryChange::Enabled(enabled) => {
                    iface.config.enabled = enabled;
                    event_queue.insert(Event::InterfaceUpdate(ifname));
                }
                InterfaceEntryChange::JoinGroup(op, group) => match op {
                    ConfigOp::Create => {
                        iface.config.join_group.insert(group);
                    }
                    ConfigOp::Delete => {
                        iface.config.join_group.remove(&group);
                    }
                },
            }
        }
    }

    Ok(())
}

fn process_event(instance: &mut Instance, event: Event) {
    match event {
        Event::InterfaceUpdate(ifname) => {
            let Some((mut instance, interfaces)) = instance.as_up() else {
                return;
            };
            let iface = interfaces.get_mut(&ifname).unwrap();
            iface.update(&mut instance);
        }
        Event::InterfaceIbusSub(ifname) => {
            let iface = instance.interfaces.get(&ifname).unwrap();
            instance.tx.ibus.interface_sub(Some(iface.name.clone()), None);
        }
    }
}

// ===== impl Instance =====

impl Provider for Instance {
    type Event = Event;
    type Resource = Resource;
    type Change = ConfigChange;

    const YANG_OPS_CONFIG: YangConfigOps<ConfigChange> = config::YANG_OPS_CONFIG;

    fn apply(&mut self, change: ConfigChange, _resource: &mut Option<Resource>, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
        apply_instance(self, change, event_queue)
    }

    fn process_event(&mut self, event: Event) {
        process_event(self, event);
    }
}

// ===== configuration defaults =====

#[allow(clippy::derivable_impls)]
impl Default for InstanceCfg {
    fn default() -> InstanceCfg {
        InstanceCfg {}
    }
}

impl Default for InterfaceCfg {
    fn default() -> InterfaceCfg {
        let last_member_query_interval = igmp::interfaces::interface::last_member_query_interval::DFLT;
        let query_interval = igmp::interfaces::interface::query_interval::DFLT;
        let query_max_response_time = igmp::interfaces::interface::query_max_response_time::DFLT;
        let robustness_variable = igmp::interfaces::interface::robustness_variable::DFLT;
        let enabled = igmp::interfaces::interface::enabled::DFLT;

        InterfaceCfg {
            last_member_query_interval,
            query_interval,
            query_max_response_time,
            robustness_variable,
            enabled,
            join_group: Default::default(),
        }
    }
}
