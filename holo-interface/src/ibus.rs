//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;

use holo_utils::ibus::{IbusMsg, IbusSender};
use holo_utils::ip::IpNetworkKind;
use holo_utils::southbound::{AddressFlags, AddressMsg, InterfaceUpdateMsg};
use ipnetwork::IpNetwork;

use crate::interface::Interface;
use crate::{Master, netlink};

// ===== global functions =====

pub(crate) async fn process_msg(master: &mut Master, msg: IbusMsg) {
    match msg {
        IbusMsg::InterfaceDump => {
            for iface in master.interfaces.iter() {
                notify_interface_update(&master.ibus_tx, iface);

                for iface_addr in iface.addresses.values() {
                    notify_addr_add(
                        &master.ibus_tx,
                        iface.name.clone(),
                        iface_addr.addr,
                        iface_addr.flags,
                    );
                }
            }
        }
        IbusMsg::InterfaceQuery { ifname, af } => {
            if let Some(iface) = master.interfaces.get_by_name(&ifname) {
                notify_interface_update(&master.ibus_tx, iface);

                for iface_addr in
                    iface.addresses.values().filter(|iface_addr| match af {
                        Some(af) => iface_addr.addr.address_family() == af,
                        None => true,
                    })
                {
                    notify_addr_add(
                        &master.ibus_tx,
                        iface.name.clone(),
                        iface_addr.addr,
                        iface_addr.flags,
                    );
                }
            }
        }
        IbusMsg::RouterIdQuery => {
            notify_router_id_update(
                &master.ibus_tx,
                master.interfaces.router_id(),
            );
        }
        IbusMsg::MacvlanAdd(msg) => {
            if let Some(iface) = master.interfaces.get_by_name(&msg.parent_name)
                && let Some(ifindex) = iface.ifindex
            {
                netlink::macvlan_create(
                    &master.netlink_handle,
                    msg.name,
                    msg.mac_address,
                    ifindex,
                )
                .await;
            }
        }
        IbusMsg::MacvlanDel(ifname) => {
            if let Some(iface) = master.interfaces.get_by_name(&ifname)
                && let Some(ifindex) = iface.ifindex
            {
                netlink::iface_delete(&master.netlink_handle, ifindex).await;
            }
        }
        IbusMsg::InterfaceIpAddRequest(msg) => {
            if let Some(iface) = master.interfaces.get_by_name(&msg.ifname)
                && let Some(ifindex) = iface.ifindex
            {
                netlink::addr_install(
                    &master.netlink_handle,
                    ifindex,
                    &msg.addr,
                )
                .await;
            }
        }
        IbusMsg::InterfaceIpDelRequest(msg) => {
            if let Some(iface) = master.interfaces.get_by_name(&msg.ifname)
                && let Some(ifindex) = iface.ifindex
            {
                netlink::addr_uninstall(
                    &master.netlink_handle,
                    ifindex,
                    &msg.addr,
                )
                .await;
            }
        }
        // Ignore other events.
        _ => {}
    }
}

pub(crate) fn notify_router_id_update(
    ibus_tx: &IbusSender,
    router_id: Option<Ipv4Addr>,
) {
    let msg = IbusMsg::RouterIdUpdate(router_id);
    notify(ibus_tx, msg);
}

pub(crate) fn notify_interface_update(ibus_tx: &IbusSender, iface: &Interface) {
    let msg = IbusMsg::InterfaceUpd(InterfaceUpdateMsg {
        ifname: iface.name.clone(),
        ifindex: iface.ifindex.unwrap_or(0),
        mtu: iface.mtu.unwrap_or(0),
        flags: iface.flags,
        mac_address: iface.mac_address,
    });
    notify(ibus_tx, msg);
}

pub(crate) fn notify_interface_del(ibus_tx: &IbusSender, ifname: String) {
    let msg = IbusMsg::InterfaceDel(ifname);
    notify(ibus_tx, msg);
}

pub(crate) fn notify_addr_add(
    ibus_tx: &IbusSender,
    ifname: String,
    addr: IpNetwork,
    flags: AddressFlags,
) {
    let msg = IbusMsg::InterfaceAddressAdd(AddressMsg {
        ifname,
        addr,
        flags,
    });
    notify(ibus_tx, msg);
}

pub(crate) fn notify_addr_del(
    ibus_tx: &IbusSender,
    ifname: String,
    addr: IpNetwork,
    flags: AddressFlags,
) {
    let msg = IbusMsg::InterfaceAddressDel(AddressMsg {
        ifname,
        addr,
        flags,
    });
    notify(ibus_tx, msg);
}

// ===== helper functions =====

fn notify(ibus_tx: &IbusSender, msg: IbusMsg) {
    let _ = ibus_tx.send(msg);
}
