//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

pub mod configuration;
pub mod rpc;
pub mod state;
pub mod yang;

use holo_northbound as northbound;
use holo_northbound::ProviderBase;
use holo_yang::ToYang;

use crate::instance::Instance;
use crate::version::{Ripng, Ripv2, Version};

// RIP version-specific code.
pub trait NorthboundVersion<V: Version> {
    fn validation_callbacks()
    -> Option<&'static northbound::configuration::ValidationCallbacks>;
    fn configuration_callbacks()
    -> &'static northbound::configuration::Callbacks<Instance<V>>;
    fn rpc_callbacks() -> &'static northbound::rpc::Callbacks<Instance<V>>;
    fn state_callbacks() -> &'static northbound::state::Callbacks<Instance<V>>;
}

// ===== impl Instance =====

impl<V> ProviderBase for Instance<V>
where
    V: Version,
{
    fn yang_modules() -> &'static [&'static str] {
        &["ietf-rip", "holo-rip"]
    }

    fn top_level_node(&self) -> String {
        format!(
            "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='{}'][name='{}']/ietf-rip:rip",
            V::PROTOCOL.to_yang(),
            self.name
        )
    }
}

// ===== impl Ripv2 =====

impl NorthboundVersion<Self> for Ripv2 {
    fn validation_callbacks()
    -> Option<&'static northbound::configuration::ValidationCallbacks> {
        Some(&configuration::VALIDATION_CALLBACKS_RIPV2)
    }

    fn configuration_callbacks()
    -> &'static northbound::configuration::Callbacks<Instance<Self>> {
        &configuration::CALLBACKS_RIPV2
    }

    fn rpc_callbacks() -> &'static northbound::rpc::Callbacks<Instance<Self>> {
        &rpc::CALLBACKS_RIPV2
    }

    fn state_callbacks() -> &'static northbound::state::Callbacks<Instance<Self>>
    {
        &state::CALLBACKS_RIPV2
    }
}

// ===== impl Ripng =====

impl NorthboundVersion<Self> for Ripng {
    fn validation_callbacks()
    -> Option<&'static northbound::configuration::ValidationCallbacks> {
        Some(&configuration::VALIDATION_CALLBACKS_RIPNG)
    }

    fn configuration_callbacks()
    -> &'static northbound::configuration::Callbacks<Instance<Self>> {
        &configuration::CALLBACKS_RIPNG
    }

    fn rpc_callbacks() -> &'static northbound::rpc::Callbacks<Instance<Self>> {
        &rpc::CALLBACKS_RIPNG
    }

    fn state_callbacks() -> &'static northbound::state::Callbacks<Instance<Self>>
    {
        &state::CALLBACKS_RIPNG
    }
}
