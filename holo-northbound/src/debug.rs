//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use tracing::{trace, trace_span};

use crate::api;
use crate::configuration::{ChangeOp, CommitPhase};

#[derive(Debug)]
pub enum Debug<'a> {
    RequestRx(&'a api::daemon::Request),
    ConfigurationChange(CommitPhase, ChangeOp, &'a str),
}

// ===== impl Debug =====

impl Debug<'_> {
    pub fn log(&self) {
        match self {
            Debug::RequestRx(message) => {
                trace_span!("northbound").in_scope(|| {
                    trace!(?message, "{}", self);
                });
            }
            Debug::ConfigurationChange(phase, operation, path) => {
                trace_span!("northbound").in_scope(|| {
                    trace!(
                        ?phase, ?operation, %path,
                        "{}", self
                    )
                });
            }
        }
    }
}

impl std::fmt::Display for Debug<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Debug::RequestRx(..) => {
                write!(f, "received request")
            }
            Debug::ConfigurationChange(..) => {
                write!(f, "configuration change")
            }
        }
    }
}
