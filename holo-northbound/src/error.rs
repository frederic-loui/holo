//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use tracing::warn;
use yang5::data::DataNodeRef;

use crate::rpc::RpcError;

// Northbound errors.
#[derive(Debug)]
pub enum Error {
    Validate(ValidationError),
    Parse { path: String, error: ParseError },
    Prepare { path: String, error: PrepareError },
    RpcNotFound,
    RpcRelay(RpcError),
    RpcCallback(RpcError),
    RelayUnreachable,
    YangInvalidPath(yang5::Error),
    YangInvalidListKeys,
    YangInvalidData(yang5::Error),
}

// Errors that can occur while validating a candidate configuration.
#[derive(Debug)]
pub struct ValidationError {
    // YANG data path of the offending data node.
    pub path: String,
    // Human-readable description of the problem.
    pub message: String,
}

// Errors that can occur while parsing a configuration change.
#[derive(Debug)]
pub enum ParseError {
    // The data node could not be found in the data tree.
    NodeNotFound(yang5::Error),
    // The list entry containing the data node could not be found in the data
    // tree.
    ListEntryNotFound,
    // A list key is missing from the data tree.
    MissingListKey(&'static str),
    // A list key holds a value that could not be parsed.
    InvalidListKey(&'static str),
    // The data node doesn't hold any value.
    MissingLeafValue,
    // The data node holds a value that could not be parsed.
    InvalidValue(String),
    // The change operation isn't valid for the data node.
    UnexpectedOperation,
}

// Errors that can occur while preparing a configuration change.
#[derive(Debug)]
pub struct PrepareError {
    // Human-readable description of the problem.
    pub message: String,
}

// Errors that can occur while applying a configuration change.
#[derive(Debug)]
pub enum ApplyError {
    EntryNotFound,
}

// ===== impl Error =====

impl Error {
    pub fn log(&self) {
        match self {
            Error::Validate(error) => {
                warn!(%error, "{}", self);
            }
            Error::Parse { path, error } => {
                warn!(%path, %error, "{}", self);
            }
            Error::Prepare { path, error } => {
                warn!(%path, %error, "{}", self);
            }
            Error::RpcNotFound => warn!("{}", self),
            Error::RpcRelay(error) => {
                warn!(%error, "{}", self);
            }
            Error::RpcCallback(error) => {
                warn!(%error, "{}", self);
            }
            Error::RelayUnreachable => warn!("{}", self),
            Error::YangInvalidPath(error) => {
                warn!(%error, "{}", self);
            }
            Error::YangInvalidListKeys => warn!("{}", self),
            Error::YangInvalidData(error) => {
                warn!(%error, "{}", self);
            }
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Validate(..) => {
                write!(f, "configuration validation failed")
            }
            Error::Parse { .. } => {
                write!(f, "failed to parse configuration change")
            }
            Error::Prepare { .. } => {
                write!(f, "failed to prepare configuration change")
            }
            Error::RpcNotFound => write!(f, "RPC/Action not found"),
            Error::RpcRelay(..) => {
                write!(f, "failed to relay RPC to the appropriate subscriber")
            }
            Error::RpcCallback(..) => {
                write!(f, "RPC callback failed")
            }
            Error::RelayUnreachable => {
                write!(
                    f,
                    "failed to relay request: the target instance is no longer running"
                )
            }
            Error::YangInvalidPath(..) => {
                write!(f, "Invalid YANG data path")
            }
            Error::YangInvalidListKeys => {
                write!(f, "Invalid YANG list keys")
            }
            Error::YangInvalidData(..) => {
                write!(f, "Invalid YANG instance data")
            }
        }
    }
}

impl std::error::Error for Error {}

// ===== impl ValidationError =====

impl ValidationError {
    pub fn new(
        dnode: &DataNodeRef<'_>,
        message: impl Into<String>,
    ) -> ValidationError {
        ValidationError {
            path: dnode.path(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

impl std::error::Error for ValidationError {}

// ===== impl ParseError =====

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::NodeNotFound(error) => {
                write!(f, "data node not found: {}", error)
            }
            ParseError::ListEntryNotFound => {
                write!(f, "list entry not found in the data tree")
            }
            ParseError::MissingListKey(name) => {
                write!(f, "missing list key: {}", name)
            }
            ParseError::InvalidListKey(name) => {
                write!(f, "invalid list key: {}", name)
            }
            ParseError::MissingLeafValue => {
                write!(f, "missing leaf value")
            }
            ParseError::InvalidValue(value) => {
                write!(f, "invalid value: {}", value)
            }
            ParseError::UnexpectedOperation => {
                write!(f, "unexpected change operation")
            }
        }
    }
}

impl std::error::Error for ParseError {}

// ===== impl PrepareError =====

impl std::fmt::Display for PrepareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for PrepareError {}

impl From<String> for PrepareError {
    fn from(message: String) -> PrepareError {
        PrepareError { message }
    }
}

impl From<&str> for PrepareError {
    fn from(message: &str) -> PrepareError {
        PrepareError {
            message: message.to_owned(),
        }
    }
}

// ===== impl ApplyError =====

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApplyError::EntryNotFound => {
                write!(f, "entry not found")
            }
        }
    }
}

impl std::error::Error for ApplyError {}
