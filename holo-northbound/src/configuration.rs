//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::sync::Arc;

use derive_new::new;
use holo_utils::yang::SchemaNodeExt;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use tracing::error;
use yang5::data::{Data, DataDiff, DataDiffOp, DataNodeRef, DataTree};
use yang5::schema::{DataValueType, SchemaNode, SchemaNodeKind};

use crate::debug::Debug;
use crate::error::{
    ApplyError, Error, ParseError, PrepareError, ValidationError,
};
use crate::{NbDaemonSender, api};

// A generic struct representing an inheritable configuration value.
//
// It contains two fields: `explicit`, which is an optional explicit value, and
// `resolved`, the resolved configuration value (inherited or explicit).
#[derive(Clone, Debug)]
pub struct InheritableConfig<T> {
    pub explicit: Option<T>,
    pub resolved: T,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum CommitPhase {
    Prepare,
    Abort,
    Apply,
}

//
// Configuration changes.
//

/// Operation carried by a configuration change.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum ChangeOp {
    Create,
    Modify,
    Delete,
}

/// Operation carried by typed configuration changes whose nodes can only be
/// created or deleted (lists, leaf-lists, presence containers and leaves of
/// type empty).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigOp {
    Create,
    Delete,
}

// Static dispatch table generated from the YANG models, mapping each
// configuration node to a parser that converts a data node into a typed
// configuration change.
pub struct YangConfigOps<C: 'static> {
    pub parse: phf::Map<&'static str, ConfigChangeParseFn<C>>,
    pub change_keys: &'static [(&'static str, ChangeOp)],
}

impl<C> YangConfigOps<C> {
    // Returns the YANG paths of all configuration nodes owned by this
    // dispatch table.
    pub fn paths(&self) -> impl Iterator<Item = &'static str> {
        self.change_keys.iter().map(|(path, _)| *path)
    }
}

/// Configuration change parsed during the Prepare phase of a transaction,
/// together with the resource allocated for it. Kept by the provider task
/// until the transaction is aborted or applied, so that each change is parsed
/// only once.
pub struct PendingChange<P: Provider> {
    key: ChangeKey,
    data_path: String,
    change: P::Change,
    resource: Option<P::Resource>,
}

/// Key identifying a configuration change.
#[derive(Clone, Debug, Eq, Hash, new, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct ChangeKey {
    pub path: String,
    pub operation: ChangeOp,
}

//
// Useful type definition(s).
//

pub type ConfigChange = (ChangeKey, String);
pub type ConfigChanges = Vec<ConfigChange>;
pub type ConfigChangeParseFn<C> =
    fn(ChangeOp, &DataNodeRef<'_>) -> Result<C, ParseError>;
pub type ValidateFn = fn(&DataTree<'static>) -> Result<(), ValidationError>;

//
// Provider northbound.
//

pub trait Provider: 'static + Sized {
    type Event;
    type Resource: Send;
    type Change: Send;

    // Generated dispatch table for typed configuration changes.
    const YANG_OPS_CONFIG: YangConfigOps<Self::Change>;

    // Returns the configuration validation functions of the provider and its
    // nested providers. Each function should validate all configuration
    // subsections owned by the corresponding crate, returning an error message
    // when the configuration is invalid.
    fn validation_fns() -> Vec<ValidateFn> {
        vec![]
    }

    // Invoked during the Prepare phase for each typed configuration change.
    // May allocate the resources required by the change, rejecting the commit
    // when the allocation fails. Configuration errors are rejected earlier, by
    // the validation functions.
    //
    // The change is passed by reference since it's consumed later, during the
    // Abort or Apply phase.
    fn prepare(
        &mut self,
        _change: &Self::Change,
        _resource: &mut Option<Self::Resource>,
        _event_queue: &mut BTreeSet<Self::Event>,
    ) -> Result<(), PrepareError> {
        Ok(())
    }

    // Invoked during the Abort phase for each typed configuration change,
    // releasing resources allocated during the Prepare phase.
    fn abort(
        &mut self,
        _change: Self::Change,
        _resource: &mut Option<Self::Resource>,
    ) {
    }

    // Invoked during the Apply phase for each typed configuration change.
    // Returns an error when the change references a configuration entry that
    // unexpectedly does not exist; the change is skipped and the error is
    // logged together with the corresponding YANG data path.
    fn apply(
        &mut self,
        _change: Self::Change,
        _resource: &mut Option<Self::Resource>,
        _event_queue: &mut BTreeSet<Self::Event>,
    ) -> Result<(), ApplyError> {
        Ok(())
    }

    fn process_event(&mut self, _event: Self::Event) {}

    fn relay_changes(
        &self,
        _changes: ConfigChanges,
    ) -> Vec<(ConfigChanges, NbDaemonSender)> {
        vec![]
    }
}

// ===== impl InheritableConfig =====

impl<T> InheritableConfig<T> {
    pub fn new(resolved: T) -> Self {
        InheritableConfig {
            explicit: None,
            resolved,
        }
    }
}

// ===== impl ChangeOp =====

impl ChangeOp {
    pub fn is_valid(&self, snode: &SchemaNode<'_>) -> bool {
        match self {
            ChangeOp::Create => ChangeOp::create_is_valid(snode),
            ChangeOp::Modify => ChangeOp::modify_is_valid(snode),
            ChangeOp::Delete => ChangeOp::delete_is_valid(snode),
        }
    }

    fn create_is_valid(snode: &SchemaNode<'_>) -> bool {
        if !snode.is_config() {
            return false;
        }

        match snode.kind() {
            SchemaNodeKind::Leaf => {
                snode.leaf_type().unwrap().base_type() == DataValueType::Empty
            }
            SchemaNodeKind::Container => !snode.is_np_container(),
            SchemaNodeKind::LeafList | SchemaNodeKind::List => true,
            _ => false,
        }
    }

    fn modify_is_valid(snode: &SchemaNode<'_>) -> bool {
        if !snode.is_config() {
            return false;
        }

        match snode.kind() {
            SchemaNodeKind::Leaf => {
                // List keys can't be modified.
                !(snode.leaf_type().unwrap().base_type()
                    == DataValueType::Empty
                    || snode.is_list_key())
            }
            _ => false,
        }
    }

    fn delete_is_valid(snode: &SchemaNode<'_>) -> bool {
        if !snode.is_config() {
            return false;
        }

        match snode.kind() {
            SchemaNodeKind::Leaf => {
                // List keys can't be deleted.
                if snode.is_list_key() {
                    return false;
                }

                // Only optional leaves can be deleted, or leaves whose
                // parent is a case statement.
                if let Some(parent) = snode.ancestors().next()
                    && parent.kind() == SchemaNodeKind::Case
                {
                    return true;
                }
                if snode.whens().next().is_some() {
                    return true;
                }
                if snode.is_mandatory() || snode.has_default() {
                    return false;
                }

                true
            }
            SchemaNodeKind::Container => !snode.is_np_container(),
            SchemaNodeKind::LeafList | SchemaNodeKind::List => true,
            _ => false,
        }
    }
}

// ===== helper functions =====

fn process_commit_local_prepare<P>(
    provider: &mut P,
    old_config: &Arc<DataTree<'static>>,
    new_config: &Arc<DataTree<'static>>,
    changes: ConfigChanges,
    pending: &mut Vec<PendingChange<P>>,
    ops: &YangConfigOps<P::Change>,
) -> Result<(), Error>
where
    P: Provider,
{
    let mut event_queue = BTreeSet::new();

    for (key, data_path) in changes {
        Debug::ConfigurationChange(
            CommitPhase::Prepare,
            key.operation,
            &key.path,
        )
        .log();

        // Get data node that is being created, modified or deleted.
        let dnode_config = match key.operation {
            ChangeOp::Create | ChangeOp::Modify => new_config,
            ChangeOp::Delete => old_config,
        };
        let Some(parse) = ops.parse.get(key.path.as_str()) else {
            continue;
        };

        // Convert the data node into a typed configuration change.
        let change = dnode_config
            .find_path(&data_path)
            .map_err(ParseError::NodeNotFound)
            .and_then(|dnode| parse(key.operation, &dnode))
            .map_err(|error| Error::Parse {
                path: data_path.clone(),
                error,
            })?;

        // Record the change even on failure, so that any resource it allocated
        // is released during the Abort phase.
        let mut entry = PendingChange {
            key,
            data_path,
            change,
            resource: None,
        };
        let result = provider
            .prepare(&entry.change, &mut entry.resource, &mut event_queue)
            .map_err(|error| Error::Prepare {
                path: entry.data_path.clone(),
                error,
            });
        pending.push(entry);
        result?;
    }

    // Process event queue once the running configuration is fully updated.
    for event in event_queue {
        provider.process_event(event);
    }

    Ok(())
}

fn process_commit_local_finish<P>(
    provider: &mut P,
    phase: CommitPhase,
    pending: Vec<PendingChange<P>>,
) where
    P: Provider,
{
    let mut event_queue = BTreeSet::new();

    for PendingChange {
        key,
        data_path,
        change,
        mut resource,
    } in pending
    {
        Debug::ConfigurationChange(phase, key.operation, &key.path).log();

        if phase == CommitPhase::Abort {
            provider.abort(change, &mut resource);
        } else if let Err(error) =
            provider.apply(change, &mut resource, &mut event_queue)
        {
            error!(%data_path, %error, "failed to apply configuration change");
        }
    }

    // Process event queue once the running configuration is fully updated.
    for event in event_queue {
        provider.process_event(event);
    }
}

fn process_commit_relayed<P>(
    provider: &P,
    phase: CommitPhase,
    old_config: &Arc<DataTree<'static>>,
    new_config: &Arc<DataTree<'static>>,
    relayed_changes: ConfigChanges,
) -> Result<(), Error>
where
    P: Provider,
{
    for (changes, nb_tx) in provider.relay_changes(relayed_changes) {
        // Send request to child task.
        let (responder_tx, responder_rx) = oneshot::channel();
        let relayed_commit = api::daemon::CommitRequest {
            phase,
            changes,
            old_config: old_config.clone(),
            new_config: new_config.clone(),
            responder: Some(responder_tx),
        };
        nb_tx
            .blocking_send(api::daemon::Request::Commit(relayed_commit))
            .map_err(|_| Error::RelayUnreachable)?;

        // Receive response.
        let _ = responder_rx
            .blocking_recv()
            .map_err(|_| Error::RelayUnreachable)??;
    }

    Ok(())
}

// ===== global functions =====

pub fn changes_from_diff(diff: &DataDiff<'static>) -> ConfigChanges {
    let mut changes = vec![];

    for (op, dnode) in diff.iter() {
        match op {
            DataDiffOp::Create => {
                for dnode in dnode.traverse() {
                    if dnode.is_default() {
                        continue;
                    }

                    let snode = dnode.schema();
                    let operation = if ChangeOp::Create.is_valid(&snode) {
                        ChangeOp::Create
                    } else if ChangeOp::Modify.is_valid(&snode) {
                        ChangeOp::Modify
                    } else {
                        continue;
                    };

                    let change_key =
                        ChangeKey::new(dnode.schema().data_path(), operation);
                    changes.push((change_key, dnode.path().to_owned()));
                }
            }
            DataDiffOp::Delete => {
                let snode = dnode.schema();
                if ChangeOp::Delete.is_valid(&snode) {
                    let change_key = ChangeKey::new(
                        dnode.schema().data_path(),
                        ChangeOp::Delete,
                    );
                    changes.push((change_key, dnode.path().to_owned()));
                    continue;
                }

                // NP-containers.
                for dnode in dnode.traverse() {
                    let snode = dnode.schema();
                    if !ChangeOp::Delete.is_valid(&snode) {
                        continue;
                    }

                    let change_key = ChangeKey::new(
                        dnode.schema().data_path(),
                        ChangeOp::Delete,
                    );
                    changes.push((change_key, dnode.path().to_owned()));
                }
            }
            DataDiffOp::Replace => {
                let snode = dnode.schema();
                if !ChangeOp::Modify.is_valid(&snode) {
                    continue;
                }

                let change_key = ChangeKey::new(
                    dnode.schema().data_path(),
                    ChangeOp::Modify,
                );
                changes.push((change_key, dnode.path().to_owned()));
            }
        }
    }

    changes
}

pub fn validate(
    fns: &[ValidateFn],
    config: &Arc<DataTree<'static>>,
) -> Result<(), Error> {
    for validate in fns {
        validate(config).map_err(Error::Validate)?;
    }

    Ok(())
}

pub(crate) fn process_commit<P>(
    provider: &mut P,
    phase: CommitPhase,
    old_config: Arc<DataTree<'static>>,
    new_config: Arc<DataTree<'static>>,
    mut changes: ConfigChanges,
    pending: &mut Vec<PendingChange<P>>,
) -> Result<api::daemon::CommitResponse, Error>
where
    P: Provider,
{
    // Move to a separate vector the changes that need to be relayed.
    let relayed_changes = changes
        .extract_if(.., |(change_key, _)| {
            !P::YANG_OPS_CONFIG
                .parse
                .contains_key(change_key.path.as_str())
        })
        .collect();

    // Process local changes. The Abort and Apply phases consume the changes
    // parsed during the Prepare phase.
    match phase {
        CommitPhase::Prepare => process_commit_local_prepare(
            provider,
            &old_config,
            &new_config,
            changes,
            pending,
            &P::YANG_OPS_CONFIG,
        )?,
        CommitPhase::Abort | CommitPhase::Apply => process_commit_local_finish(
            provider,
            phase,
            std::mem::take(pending),
        ),
    }

    // Process relayed changes.
    process_commit_relayed(
        provider,
        phase,
        &old_config,
        &new_config,
        relayed_changes,
    )?;

    Ok(api::daemon::CommitResponse {})
}
