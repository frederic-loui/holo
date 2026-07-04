//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::collections::BTreeSet;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, atomic};

use holo_northbound::configuration::{Provider, YangConfigOps};
use holo_northbound::error::ApplyError;
use holo_utils::ip::AddressFamily;
use holo_utils::mac_addr::MacAddr;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};

use crate::ibus;
use crate::instance::{Instance, Version, fsm};
use crate::interface::Interface;
use crate::northbound::yang_gen::config::{
    self, ConfigChange, Ipv4VrrpInstanceChange, Ipv4VrrpInstanceEntryChange, Ipv4VrrpInstanceVirtualIpv4AddressChange, Ipv6VrrpInstanceChange, Ipv6VrrpInstanceEntryChange, Ipv6VrrpInstanceVirtualIpv6AddressChange,
    VrrpTraceOptionsFlagChange,
};
use crate::northbound::yang_gen::interfaces;

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    InstanceStart { vrid: u8, af: AddressFamily },
    InstanceDelete { vrid: u8, af: AddressFamily },
    VirtualAddressCreate { vrid: u8, af: AddressFamily, addr: IpNetwork },
    VirtualAddressDelete { vrid: u8, af: AddressFamily, addr: IpNetwork },
    ResetTimer { vrid: u8, af: AddressFamily },
}

// ===== configuration structs =====

#[derive(Debug, Default)]
pub struct InterfaceCfg {
    pub trace_opts: TraceOptions,
}

#[derive(Debug)]
pub struct InstanceCfg {
    pub log_state_change: bool,
    pub preempt: bool,
    pub priority: u8,
    pub advertise_interval: u16,
    pub version: Version,
    pub virtual_addresses: BTreeSet<IpNetwork>,
}

#[derive(Clone, Copy, Debug)]
pub enum TraceOption {
    Events,
    InternalBus,
    Packets,
}

#[derive(Debug, Default)]
pub struct TraceOptions {
    pub events: bool,
    pub ibus: bool,
    pub packets: Arc<AtomicBool>,
}

// ===== helper functions =====

fn apply_interface(interface: &mut Interface, change: ConfigChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        ConfigChange::Ipv4VrrpInstance(keys, change) => {
            apply_ipv4_vrrp_instance(interface, keys.vrid, change, event_queue)?;
        }
        ConfigChange::Ipv6VrrpInstance(keys, change) => {
            apply_ipv6_vrrp_instance(interface, keys.vrid, change, event_queue)?;
        }
        ConfigChange::VrrpTraceOptionsFlag(keys, change) => {
            apply_vrrp_trace_options_flag(interface, keys.name, change)?;
        }
    }

    Ok(())
}

fn apply_ipv4_vrrp_instance(interface: &mut Interface, vrid: u8, change: Ipv4VrrpInstanceChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    let af = AddressFamily::Ipv4;

    match change {
        Ipv4VrrpInstanceChange::Create => {
            let mut instance = Instance::new(vrid, af);
            instance.state.last_event = fsm::Event::Startup;
            interface.vrrp_ipv4_instances.insert(vrid, instance);

            event_queue.insert(Event::InstanceStart {
                vrid,
                af,
            });
        }
        Ipv4VrrpInstanceChange::Delete => {
            event_queue.insert(Event::InstanceDelete {
                vrid,
                af,
            });
        }
        Ipv4VrrpInstanceChange::Entry(change) => {
            let instance = interface.vrrp_ipv4_instances.get_mut(&vrid).ok_or(ApplyError::EntryNotFound)?;
            match change {
                Ipv4VrrpInstanceEntryChange::Version(version) => {
                    let version = match version.as_str() {
                        "ietf-vrrp:vrrp-v2" => Version::V2,
                        "ietf-vrrp:vrrp-v3" => Version::V3(af),
                        _ => return Ok(()),
                    };
                    instance.config.version = version;
                }
                Ipv4VrrpInstanceEntryChange::LogStateChange(log_state_change) => {
                    instance.config.log_state_change = log_state_change;
                }
                Ipv4VrrpInstanceEntryChange::PreemptEnabled(preempt) => {
                    instance.config.preempt = preempt;
                }
                Ipv4VrrpInstanceEntryChange::Priority(priority) => {
                    instance.config.priority = priority;
                    event_queue.insert(Event::ResetTimer {
                        vrid,
                        af,
                    });
                }
                Ipv4VrrpInstanceEntryChange::AdvertiseIntervalSec(advertise_interval) => {
                    if let Some(advertise_interval) = advertise_interval {
                        instance.config.advertise_interval = advertise_interval.into();
                    }
                }
                Ipv4VrrpInstanceEntryChange::AdvertiseIntervalCentiSec(advertise_interval) => {
                    if let Some(advertise_interval) = advertise_interval {
                        instance.config.advertise_interval = advertise_interval;
                    }
                }
                Ipv4VrrpInstanceEntryChange::VirtualIpv4Address(keys, change) => {
                    let addr = IpNetwork::V4(Ipv4Network::from(keys.ipv4_address));
                    apply_ipv4_vrrp_instance_virtual_address(instance, vrid, af, addr, change, event_queue)?;
                }
            }
        }
    }

    Ok(())
}

fn apply_ipv6_vrrp_instance(interface: &mut Interface, vrid: u8, change: Ipv6VrrpInstanceChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    let af = AddressFamily::Ipv6;

    match change {
        Ipv6VrrpInstanceChange::Create => {
            let mut instance = Instance::new(vrid, af);
            instance.state.last_event = fsm::Event::Startup;
            interface.vrrp_ipv6_instances.insert(vrid, instance);

            event_queue.insert(Event::InstanceStart {
                vrid,
                af,
            });
        }
        Ipv6VrrpInstanceChange::Delete => {
            event_queue.insert(Event::InstanceDelete {
                vrid,
                af,
            });
        }
        Ipv6VrrpInstanceChange::Entry(change) => {
            let instance = interface.vrrp_ipv6_instances.get_mut(&vrid).ok_or(ApplyError::EntryNotFound)?;
            match change {
                Ipv6VrrpInstanceEntryChange::Version(_version) => {
                    // Nothing to do.
                }
                Ipv6VrrpInstanceEntryChange::LogStateChange(log_state_change) => {
                    instance.config.log_state_change = log_state_change;
                }
                Ipv6VrrpInstanceEntryChange::PreemptEnabled(preempt) => {
                    instance.config.preempt = preempt;
                }
                Ipv6VrrpInstanceEntryChange::Priority(priority) => {
                    instance.config.priority = priority;
                    event_queue.insert(Event::ResetTimer {
                        vrid,
                        af,
                    });
                }
                Ipv6VrrpInstanceEntryChange::AdvertiseIntervalCentiSec(advertise_interval) => {
                    instance.config.advertise_interval = advertise_interval;
                }
                Ipv6VrrpInstanceEntryChange::VirtualIpv6Address(keys, change) => {
                    let addr = IpNetwork::V6(Ipv6Network::from(keys.ipv6_address));
                    apply_ipv6_vrrp_instance_virtual_address(instance, vrid, af, addr, change, event_queue)?;
                }
            }
        }
    }

    Ok(())
}

fn apply_ipv4_vrrp_instance_virtual_address(instance: &mut Instance, vrid: u8, af: AddressFamily, addr: IpNetwork, change: Ipv4VrrpInstanceVirtualIpv4AddressChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        Ipv4VrrpInstanceVirtualIpv4AddressChange::Create => {
            instance.config.virtual_addresses.insert(addr);
            event_queue.insert(Event::VirtualAddressCreate {
                vrid,
                af,
                addr,
            });
        }
        Ipv4VrrpInstanceVirtualIpv4AddressChange::Delete => {
            instance.config.virtual_addresses.remove(&addr);
            event_queue.insert(Event::VirtualAddressDelete {
                vrid,
                af,
                addr,
            });
        }
    }

    Ok(())
}

fn apply_ipv6_vrrp_instance_virtual_address(instance: &mut Instance, vrid: u8, af: AddressFamily, addr: IpNetwork, change: Ipv6VrrpInstanceVirtualIpv6AddressChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        Ipv6VrrpInstanceVirtualIpv6AddressChange::Create => {
            instance.config.virtual_addresses.insert(addr);
            event_queue.insert(Event::VirtualAddressCreate {
                vrid,
                af,
                addr,
            });
        }
        Ipv6VrrpInstanceVirtualIpv6AddressChange::Delete => {
            instance.config.virtual_addresses.remove(&addr);
            event_queue.insert(Event::VirtualAddressDelete {
                vrid,
                af,
                addr,
            });
        }
    }

    Ok(())
}

fn apply_vrrp_trace_options_flag(interface: &mut Interface, trace_opt: TraceOption, change: VrrpTraceOptionsFlagChange) -> Result<(), ApplyError> {
    let trace_opts = &mut interface.config.trace_opts;
    match change {
        VrrpTraceOptionsFlagChange::Create => match trace_opt {
            TraceOption::Events => trace_opts.events = true,
            TraceOption::InternalBus => trace_opts.ibus = true,
            TraceOption::Packets => trace_opts.packets.store(true, atomic::Ordering::Relaxed),
        },
        VrrpTraceOptionsFlagChange::Delete => match trace_opt {
            TraceOption::Events => trace_opts.events = false,
            TraceOption::InternalBus => trace_opts.ibus = false,
            TraceOption::Packets => trace_opts.packets.store(false, atomic::Ordering::Relaxed),
        },
    }

    Ok(())
}

fn process_event(interface: &mut Interface, event: Event) {
    match event {
        Event::InstanceStart {
            vrid,
            af,
        } => {
            let (interface, instance) = interface.get_instance(vrid, af).unwrap();

            let virtual_mac_addr = match af {
                AddressFamily::Ipv4 => MacAddr::from([0x00, 0x00, 0x5e, 0x00, 0x01, vrid]),
                AddressFamily::Ipv6 => MacAddr::from([0x00, 0x00, 0x5e, 0x00, 0x02, vrid]),
            };
            ibus::tx::mvlan_create(&interface.tx.ibus, interface.name.to_owned(), instance.mvlan.name.clone(), virtual_mac_addr);
        }
        Event::InstanceDelete {
            vrid,
            af,
        } => {
            let mut instance = match af {
                AddressFamily::Ipv4 => interface.vrrp_ipv4_instances.remove(&vrid).unwrap(),
                AddressFamily::Ipv6 => interface.vrrp_ipv6_instances.remove(&vrid).unwrap(),
            };
            let interface = interface.as_view();

            // Shut down the instance.
            instance.shutdown(&interface);

            // Delete macvlan interface.
            ibus::tx::mvlan_delete(&interface.tx.ibus, &instance.mvlan.name);
        }
        Event::VirtualAddressCreate {
            vrid,
            af,
            addr,
        } => {
            let (interface, instance) = interface.get_instance(vrid, af).unwrap();

            if instance.state.state == fsm::State::Master {
                ibus::tx::ip_addr_add(&interface.tx.ibus, &instance.mvlan.name, addr);
                instance.timer_set(&interface);
            }
        }
        Event::VirtualAddressDelete {
            vrid,
            af,
            addr,
        } => {
            let (interface, instance) = interface.get_instance(vrid, af).unwrap();

            if instance.state.state == fsm::State::Master {
                ibus::tx::ip_addr_del(&interface.tx.ibus, &instance.mvlan.name, addr);
                instance.timer_set(&interface);
            }
        }
        Event::ResetTimer {
            vrid,
            af,
        } => {
            let (_, instance) = interface.get_instance(vrid, af).unwrap();
            instance.timer_reset();
        }
    }
}

// ===== impl Interface =====

impl Provider for Interface {
    type Event = Event;
    type Resource = Resource;
    type Change = ConfigChange;

    const YANG_OPS_CONFIG: YangConfigOps<ConfigChange> = config::YANG_OPS_CONFIG;

    fn apply(&mut self, change: ConfigChange, _resource: &mut Option<Resource>, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
        apply_interface(self, change, event_queue)
    }

    fn process_event(&mut self, event: Event) {
        process_event(self, event);
    }
}

// ===== configuration helpers =====

impl InstanceCfg {
    pub(crate) const fn master_down_interval(&self) -> u32 {
        (3 * self.advertise_interval as u32) + self.skew_time() as u32
    }

    pub(crate) const fn skew_time(&self) -> f32 {
        (256_f32 - self.priority as f32) / 256_f32
    }
}

// ===== configuration defaults =====

impl InstanceCfg {
    pub(crate) fn default(af: AddressFamily) -> InstanceCfg {
        match af {
            AddressFamily::Ipv4 => {
                use interfaces::interface::ipv4::vrrp;

                let log_state_change = vrrp::vrrp_instance::log_state_change::DFLT;
                let preempt = vrrp::vrrp_instance::preempt::enabled::DFLT;
                let priority = vrrp::vrrp_instance::priority::DFLT;
                let advertise_interval = vrrp::vrrp_instance::advertise_interval_sec::DFLT;
                InstanceCfg {
                    log_state_change,
                    preempt,
                    priority,
                    advertise_interval: advertise_interval.into(),
                    virtual_addresses: Default::default(),
                    version: Version::V2,
                }
            }
            AddressFamily::Ipv6 => {
                use interfaces::interface::ipv6::vrrp;

                let log_state_change = vrrp::vrrp_instance::log_state_change::DFLT;
                let preempt = vrrp::vrrp_instance::preempt::enabled::DFLT;
                let priority = vrrp::vrrp_instance::priority::DFLT;
                let advertise_interval = vrrp::vrrp_instance::advertise_interval_centi_sec::DFLT;
                InstanceCfg {
                    log_state_change,
                    preempt,
                    priority,
                    advertise_interval,
                    virtual_addresses: Default::default(),
                    version: Version::V3(AddressFamily::Ipv6),
                }
            }
        }
    }
}
