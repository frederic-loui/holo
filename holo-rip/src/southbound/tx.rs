//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::ibus::{IbusMsg, IbusSender};
use holo_utils::southbound::{Nexthop, RouteKeyMsg, RouteMsg};

use crate::route::{Route, RouteType};
use crate::version::Version;

// ===== impl InstanceSouthboundTx =====

// Install RIP route in the RIB.
pub(crate) fn route_install<V>(
    ibus_tx: &IbusSender,
    route: &Route<V>,
    distance: u8,
) where
    V: Version,
{
    if route.route_type != RouteType::Rip {
        return;
    }

    // Fill-in message.
    let msg = RouteMsg {
        protocol: V::PROTOCOL,
        prefix: route.prefix.into(),
        distance: distance.into(),
        metric: route.metric.get() as u32,
        tag: Some(route.tag.into()),
        nexthops: [Nexthop::Address {
            ifindex: route.ifindex,
            addr: route.nexthop.unwrap().into(),
            labels: Vec::new(),
        }]
        .into(),
    };

    // Send message.
    let msg = IbusMsg::RouteIpAdd(msg);
    let _ = ibus_tx.send(msg);
}

// Uninstall RIP route from the RIB.
pub(crate) fn route_uninstall<V>(ibus_tx: &IbusSender, route: &Route<V>)
where
    V: Version,
{
    if route.route_type != RouteType::Rip {
        return;
    }

    // Fill-in message.
    let msg = RouteKeyMsg {
        protocol: V::PROTOCOL,
        prefix: route.prefix.into(),
    };

    // Send message.
    let msg = IbusMsg::RouteIpDel(msg);
    let _ = ibus_tx.send(msg);
}
