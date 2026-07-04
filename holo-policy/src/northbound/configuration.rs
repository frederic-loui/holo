//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeSet, btree_map};
use std::sync::Arc;

use holo_northbound::configuration::{ConfigOp, Provider, YangConfigOps};
use holo_northbound::error::ApplyError;
use holo_utils::bgp::{Comm, ExtComm, Extv6Comm, LargeComm};
use holo_utils::ip::AddressFamily;
use holo_utils::policy::{
    BgpEqOperator, BgpPolicyAction, BgpPolicyActionType, BgpPolicyCondition, BgpPolicyConditionType, BgpSetCommMethod, BgpSetCommOptions, IpPrefixRange, MatchSetRestrictedType, MatchSetType, MetricModification, NeighborSet, Policy,
    PolicyAction, PolicyActionType, PolicyCondition, PolicyConditionType, PolicyStmt, PrefixSet, TagSet,
};
use holo_yang::TryFromYang;

use crate::Master;
use crate::northbound::yang_gen::config::{
    self, ConfigChange, DefinedSetsBgpDefinedSetsAsPathSetChange, DefinedSetsBgpDefinedSetsAsPathSetEntryChange, DefinedSetsBgpDefinedSetsCommunitySetChange, DefinedSetsBgpDefinedSetsCommunitySetEntryChange,
    DefinedSetsBgpDefinedSetsExtCommunitySetChange, DefinedSetsBgpDefinedSetsExtCommunitySetEntryChange, DefinedSetsBgpDefinedSetsIpv6ExtCommunitySetChange, DefinedSetsBgpDefinedSetsIpv6ExtCommunitySetEntryChange,
    DefinedSetsBgpDefinedSetsLargeCommunitySetChange, DefinedSetsBgpDefinedSetsLargeCommunitySetEntryChange, DefinedSetsBgpDefinedSetsNextHopSetChange, DefinedSetsBgpDefinedSetsNextHopSetEntryChange, DefinedSetsNeighborSetChange,
    DefinedSetsNeighborSetEntryChange, DefinedSetsPrefixSetChange, DefinedSetsPrefixSetEntryChange, DefinedSetsTagSetChange, DefinedSetsTagSetEntryChange, PolicyDefinitionChange, PolicyDefinitionEntryChange,
    PolicyDefinitionStatementChange, PolicyDefinitionStatementEntryChange,
};

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    MatchSetsUpdate,
    PolicyChange(String),
    PolicyDelete(String),
}

// ===== helper functions =====

fn apply_master(master: &mut Master, change: ConfigChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        ConfigChange::DefinedSetsPrefixSet(keys, change) => {
            apply_prefix_set(master, keys.mode, keys.name, change, event_queue)?;
        }
        ConfigChange::DefinedSetsNeighborSet(keys, change) => {
            apply_neighbor_set(master, keys.name, change, event_queue)?;
        }
        ConfigChange::DefinedSetsTagSet(keys, change) => {
            apply_tag_set(master, keys.name, change, event_queue)?;
        }
        ConfigChange::DefinedSetsBgpDefinedSetsAsPathSet(keys, change) => {
            apply_bgp_as_path_set(master, keys.name, change, event_queue)?;
        }
        ConfigChange::DefinedSetsBgpDefinedSetsCommunitySet(keys, change) => {
            apply_bgp_community_set(master, keys.name, change, event_queue)?;
        }
        ConfigChange::DefinedSetsBgpDefinedSetsExtCommunitySet(keys, change) => {
            apply_bgp_ext_community_set(master, keys.name, change, event_queue)?;
        }
        ConfigChange::DefinedSetsBgpDefinedSetsIpv6ExtCommunitySet(keys, change) => {
            apply_bgp_ipv6_ext_community_set(master, keys.name, change, event_queue)?;
        }
        ConfigChange::DefinedSetsBgpDefinedSetsLargeCommunitySet(keys, change) => {
            apply_bgp_large_community_set(master, keys.name, change, event_queue)?;
        }
        ConfigChange::DefinedSetsBgpDefinedSetsNextHopSet(keys, change) => {
            apply_bgp_next_hop_set(master, keys.name, change, event_queue)?;
        }
        ConfigChange::PolicyDefinition(keys, change) => {
            apply_policy_definition(master, keys.name, change, event_queue)?;
        }
    }

    Ok(())
}

fn apply_prefix_set(master: &mut Master, mode: AddressFamily, name: String, change: DefinedSetsPrefixSetChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        DefinedSetsPrefixSetChange::Create => {
            let set = PrefixSet {
                name: name.clone(),
                mode,
                prefixes: Default::default(),
            };
            master.match_sets.prefixes.insert((name, mode), set);
        }
        DefinedSetsPrefixSetChange::Delete => {
            master.match_sets.prefixes.remove(&(name, mode));
            event_queue.insert(Event::MatchSetsUpdate);
        }
        DefinedSetsPrefixSetChange::Entry(change) => {
            let set = master.match_sets.prefixes.get_mut(&(name, mode)).ok_or(ApplyError::EntryNotFound)?;
            match change {
                DefinedSetsPrefixSetEntryChange::PrefixList(keys, change) => {
                    let prefix_range = IpPrefixRange {
                        prefix: keys.ip_prefix,
                        masklen_lower: keys.mask_length_lower,
                        masklen_upper: keys.mask_length_upper,
                    };
                    apply_prefix_list(set, prefix_range, change, event_queue)?;
                }
            }
        }
    }

    Ok(())
}

fn apply_prefix_list(set: &mut PrefixSet, prefix_range: IpPrefixRange, change: config::DefinedSetsPrefixSetPrefixListChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        config::DefinedSetsPrefixSetPrefixListChange::Create => {
            set.prefixes.insert(prefix_range);
        }
        config::DefinedSetsPrefixSetPrefixListChange::Delete => {
            set.prefixes.remove(&prefix_range);
        }
    }
    event_queue.insert(Event::MatchSetsUpdate);

    Ok(())
}

fn apply_neighbor_set(master: &mut Master, name: String, change: DefinedSetsNeighborSetChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        DefinedSetsNeighborSetChange::Create => {
            let set = NeighborSet {
                name: name.clone(),
                addrs: Default::default(),
            };
            master.match_sets.neighbors.insert(name, set);
        }
        DefinedSetsNeighborSetChange::Delete => {
            master.match_sets.neighbors.remove(&name);
            event_queue.insert(Event::MatchSetsUpdate);
        }
        DefinedSetsNeighborSetChange::Entry(change) => {
            let set = master.match_sets.neighbors.get_mut(&name).ok_or(ApplyError::EntryNotFound)?;
            match change {
                DefinedSetsNeighborSetEntryChange::Address(op, addr) => {
                    match op {
                        ConfigOp::Create => {
                            set.addrs.insert(addr);
                        }
                        ConfigOp::Delete => {
                            set.addrs.remove(&addr);
                        }
                    }
                    event_queue.insert(Event::MatchSetsUpdate);
                }
            }
        }
    }

    Ok(())
}

fn apply_tag_set(master: &mut Master, name: String, change: DefinedSetsTagSetChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        DefinedSetsTagSetChange::Create => {
            let set = TagSet {
                name: name.clone(),
                tags: Default::default(),
            };
            master.match_sets.tags.insert(name, set);
        }
        DefinedSetsTagSetChange::Delete => {
            master.match_sets.tags.remove(&name);
            event_queue.insert(Event::MatchSetsUpdate);
        }
        DefinedSetsTagSetChange::Entry(change) => {
            let set = master.match_sets.tags.get_mut(&name).ok_or(ApplyError::EntryNotFound)?;
            match change {
                DefinedSetsTagSetEntryChange::TagValue(op, tag) => {
                    match op {
                        ConfigOp::Create => {
                            set.tags.insert(tag.0);
                        }
                        ConfigOp::Delete => {
                            set.tags.remove(&tag.0);
                        }
                    }
                    event_queue.insert(Event::MatchSetsUpdate);
                }
            }
        }
    }

    Ok(())
}

fn apply_bgp_as_path_set(master: &mut Master, name: String, change: DefinedSetsBgpDefinedSetsAsPathSetChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        DefinedSetsBgpDefinedSetsAsPathSetChange::Create => {
            master.match_sets.bgp.as_paths.insert(name, Default::default());
        }
        DefinedSetsBgpDefinedSetsAsPathSetChange::Delete => {
            master.match_sets.bgp.as_paths.remove(&name);
            event_queue.insert(Event::MatchSetsUpdate);
        }
        DefinedSetsBgpDefinedSetsAsPathSetChange::Entry(change) => {
            let set = master.match_sets.bgp.as_paths.get_mut(&name).ok_or(ApplyError::EntryNotFound)?;
            match change {
                DefinedSetsBgpDefinedSetsAsPathSetEntryChange::Member(op, member) => {
                    // AS path regular expressions aren't supported.
                    let Ok(member) = member.parse() else {
                        return Ok(());
                    };
                    match op {
                        ConfigOp::Create => {
                            set.insert(member);
                        }
                        ConfigOp::Delete => {
                            set.remove(&member);
                        }
                    }
                    event_queue.insert(Event::MatchSetsUpdate);
                }
            }
        }
    }

    Ok(())
}

fn apply_bgp_community_set(master: &mut Master, name: String, change: DefinedSetsBgpDefinedSetsCommunitySetChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        DefinedSetsBgpDefinedSetsCommunitySetChange::Create => {
            master.match_sets.bgp.comms.insert(name, Default::default());
        }
        DefinedSetsBgpDefinedSetsCommunitySetChange::Delete => {
            master.match_sets.bgp.comms.remove(&name);
            event_queue.insert(Event::MatchSetsUpdate);
        }
        DefinedSetsBgpDefinedSetsCommunitySetChange::Entry(change) => {
            let set = master.match_sets.bgp.comms.get_mut(&name).ok_or(ApplyError::EntryNotFound)?;
            match change {
                DefinedSetsBgpDefinedSetsCommunitySetEntryChange::Member(op, member) => {
                    // Community regular expressions aren't supported.
                    let Some(member) = Comm::try_from_yang(&member) else {
                        return Ok(());
                    };
                    match op {
                        ConfigOp::Create => {
                            set.insert(member);
                        }
                        ConfigOp::Delete => {
                            set.remove(&member);
                        }
                    }
                    event_queue.insert(Event::MatchSetsUpdate);
                }
            }
        }
    }

    Ok(())
}

fn apply_bgp_ext_community_set(master: &mut Master, name: String, change: DefinedSetsBgpDefinedSetsExtCommunitySetChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        DefinedSetsBgpDefinedSetsExtCommunitySetChange::Create => {
            master.match_sets.bgp.ext_comms.insert(name, Default::default());
        }
        DefinedSetsBgpDefinedSetsExtCommunitySetChange::Delete => {
            master.match_sets.bgp.ext_comms.remove(&name);
            event_queue.insert(Event::MatchSetsUpdate);
        }
        DefinedSetsBgpDefinedSetsExtCommunitySetChange::Entry(change) => {
            let set = master.match_sets.bgp.ext_comms.get_mut(&name).ok_or(ApplyError::EntryNotFound)?;
            match change {
                DefinedSetsBgpDefinedSetsExtCommunitySetEntryChange::Member(op, member) => {
                    // Unsupported extended community formats are ignored.
                    let Some(member) = ExtComm::try_from_yang(&member) else {
                        return Ok(());
                    };
                    match op {
                        ConfigOp::Create => {
                            set.insert(member);
                        }
                        ConfigOp::Delete => {
                            set.remove(&member);
                        }
                    }
                    event_queue.insert(Event::MatchSetsUpdate);
                }
            }
        }
    }

    Ok(())
}

fn apply_bgp_ipv6_ext_community_set(master: &mut Master, name: String, change: DefinedSetsBgpDefinedSetsIpv6ExtCommunitySetChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        DefinedSetsBgpDefinedSetsIpv6ExtCommunitySetChange::Create => {
            master.match_sets.bgp.extv6_comms.insert(name, Default::default());
        }
        DefinedSetsBgpDefinedSetsIpv6ExtCommunitySetChange::Delete => {
            master.match_sets.bgp.extv6_comms.remove(&name);
            event_queue.insert(Event::MatchSetsUpdate);
        }
        DefinedSetsBgpDefinedSetsIpv6ExtCommunitySetChange::Entry(change) => {
            let set = master.match_sets.bgp.extv6_comms.get_mut(&name).ok_or(ApplyError::EntryNotFound)?;
            match change {
                DefinedSetsBgpDefinedSetsIpv6ExtCommunitySetEntryChange::Member(op, member) => {
                    // Unsupported IPv6 extended community formats are ignored.
                    let Some(member) = Extv6Comm::try_from_yang(&member) else {
                        return Ok(());
                    };
                    match op {
                        ConfigOp::Create => {
                            set.insert(member);
                        }
                        ConfigOp::Delete => {
                            set.remove(&member);
                        }
                    }
                    event_queue.insert(Event::MatchSetsUpdate);
                }
            }
        }
    }

    Ok(())
}

fn apply_bgp_large_community_set(master: &mut Master, name: String, change: DefinedSetsBgpDefinedSetsLargeCommunitySetChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        DefinedSetsBgpDefinedSetsLargeCommunitySetChange::Create => {
            master.match_sets.bgp.large_comms.insert(name, Default::default());
        }
        DefinedSetsBgpDefinedSetsLargeCommunitySetChange::Delete => {
            master.match_sets.bgp.large_comms.remove(&name);
            event_queue.insert(Event::MatchSetsUpdate);
        }
        DefinedSetsBgpDefinedSetsLargeCommunitySetChange::Entry(change) => {
            let set = master.match_sets.bgp.large_comms.get_mut(&name).ok_or(ApplyError::EntryNotFound)?;
            match change {
                DefinedSetsBgpDefinedSetsLargeCommunitySetEntryChange::Member(op, member) => {
                    // Large community regular expressions aren't supported.
                    let Some(member) = LargeComm::try_from_yang(&member) else {
                        return Ok(());
                    };
                    match op {
                        ConfigOp::Create => {
                            set.insert(member);
                        }
                        ConfigOp::Delete => {
                            set.remove(&member);
                        }
                    }
                    event_queue.insert(Event::MatchSetsUpdate);
                }
            }
        }
    }

    Ok(())
}

fn apply_bgp_next_hop_set(master: &mut Master, name: String, change: DefinedSetsBgpDefinedSetsNextHopSetChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        DefinedSetsBgpDefinedSetsNextHopSetChange::Create => {
            master.match_sets.bgp.nexthops.insert(name, Default::default());
        }
        DefinedSetsBgpDefinedSetsNextHopSetChange::Delete => {
            master.match_sets.bgp.nexthops.remove(&name);
            event_queue.insert(Event::MatchSetsUpdate);
        }
        DefinedSetsBgpDefinedSetsNextHopSetChange::Entry(change) => {
            let set = master.match_sets.bgp.nexthops.get_mut(&name).ok_or(ApplyError::EntryNotFound)?;
            match change {
                DefinedSetsBgpDefinedSetsNextHopSetEntryChange::NextHop(op, next_hop) => {
                    match op {
                        ConfigOp::Create => {
                            set.insert(next_hop);
                        }
                        ConfigOp::Delete => {
                            set.remove(&next_hop);
                        }
                    }
                    event_queue.insert(Event::MatchSetsUpdate);
                }
            }
        }
    }

    Ok(())
}

fn apply_policy_definition(master: &mut Master, name: String, change: PolicyDefinitionChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        PolicyDefinitionChange::Create => {
            let policy = Policy {
                name: name.clone(),
                stmts: Default::default(),
            };
            master.policies.insert(name, policy);
        }
        PolicyDefinitionChange::Delete => {
            master.policies.remove(&name);
            event_queue.insert(Event::PolicyDelete(name));
        }
        PolicyDefinitionChange::Entry(change) => {
            let policy = master.policies.get_mut(&name).ok_or(ApplyError::EntryNotFound)?;
            match change {
                PolicyDefinitionEntryChange::Statement(keys, change) => {
                    apply_statement(policy, keys.name, change)?;
                    event_queue.insert(Event::PolicyChange(name));
                }
            }
        }
    }

    Ok(())
}

// Returns true if the change affects the policy definition.
fn apply_statement(policy: &mut Policy, stmt_name: String, change: PolicyDefinitionStatementChange) -> Result<(), ApplyError> {
    match change {
        PolicyDefinitionStatementChange::Create => {
            let stmt = PolicyStmt::new(stmt_name.clone());
            policy.stmts.insert(stmt_name, stmt);
        }
        PolicyDefinitionStatementChange::Delete => {
            policy.stmts.remove(&stmt_name);
        }
        PolicyDefinitionStatementChange::Entry(change) => {
            let stmt = policy.stmts.get_mut(&stmt_name).ok_or(ApplyError::EntryNotFound)?;
            match change {
                PolicyDefinitionStatementEntryChange::ConditionsCallPolicy(call_policy) => match call_policy {
                    Some(call_policy) => {
                        stmt.condition_add(PolicyCondition::CallPolicy(call_policy));
                    }
                    None => {
                        stmt.condition_remove(PolicyConditionType::CallPolicy);
                    }
                },
                PolicyDefinitionStatementEntryChange::ConditionsSourceProtocol(protocol) => match protocol {
                    Some(protocol) => {
                        stmt.condition_add(PolicyCondition::SrcProtocol(protocol));
                    }
                    None => {
                        stmt.condition_remove(PolicyConditionType::SrcProtocol);
                    }
                },
                PolicyDefinitionStatementEntryChange::ConditionsMatchInterfaceInterface(interface) => match interface {
                    Some(interface) => {
                        stmt.condition_add(PolicyCondition::MatchInterface(interface));
                    }
                    None => {
                        stmt.condition_remove(PolicyConditionType::MatchInterface);
                    }
                },
                PolicyDefinitionStatementEntryChange::ConditionsMatchPrefixSetPrefixSet(prefix_set) => match prefix_set {
                    Some(prefix_set) => {
                        stmt.condition_add(PolicyCondition::MatchPrefixSet(prefix_set));
                    }
                    None => {
                        stmt.condition_remove(PolicyConditionType::MatchPrefixSet);
                    }
                },
                PolicyDefinitionStatementEntryChange::ConditionsMatchPrefixSetMatchSetOptions(match_type) => {
                    stmt.prefix_set_match_type = match_type;
                }
                PolicyDefinitionStatementEntryChange::ConditionsMatchNeighborSetNeighborSet(neighbor_set) => match neighbor_set {
                    Some(neighbor_set) => {
                        stmt.condition_add(PolicyCondition::MatchNeighborSet(neighbor_set));
                    }
                    None => {
                        stmt.condition_remove(PolicyConditionType::MatchNeighborSet);
                    }
                },
                PolicyDefinitionStatementEntryChange::ConditionsMatchTagSetTagSet(tag_set) => match tag_set {
                    Some(tag_set) => {
                        stmt.condition_add(PolicyCondition::MatchTagSet(tag_set));
                    }
                    None => {
                        stmt.condition_remove(PolicyConditionType::MatchTagSet);
                    }
                },
                PolicyDefinitionStatementEntryChange::ConditionsMatchTagSetMatchSetOptions(match_type) => {
                    stmt.tag_set_match_type = match_type;
                }
                PolicyDefinitionStatementEntryChange::ConditionsMatchRouteTypeRouteType(op, route_type) => match op {
                    ConfigOp::Create => {
                        if let PolicyCondition::MatchRouteType(route_types) = stmt.conditions.entry(PolicyConditionType::MatchRouteType).or_insert_with(|| PolicyCondition::MatchRouteType(BTreeSet::new())) {
                            route_types.insert(route_type);
                        }
                    }
                    ConfigOp::Delete => {
                        if let btree_map::Entry::Occupied(mut entry) = stmt.conditions.entry(PolicyConditionType::MatchRouteType)
                            && let PolicyCondition::MatchRouteType(route_types) = entry.get_mut()
                        {
                            route_types.remove(&route_type);
                            if route_types.is_empty() {
                                entry.remove();
                            }
                        }
                    }
                },
                PolicyDefinitionStatementEntryChange::ActionsPolicyResult(policy_result) => match policy_result {
                    Some(policy_result) => {
                        let accept = policy_result == "accept-route";
                        stmt.action_add(PolicyAction::Accept(accept));
                    }
                    None => {
                        stmt.action_remove(PolicyActionType::Accept);
                    }
                },
                PolicyDefinitionStatementEntryChange::ActionsSetMetricTypeMetricType(metric_type) => match metric_type {
                    Some(metric_type) => {
                        stmt.action_add(PolicyAction::SetMetricType(metric_type));
                    }
                    None => {
                        stmt.action_remove(PolicyActionType::SetMetricType);
                    }
                },
                PolicyDefinitionStatementEntryChange::ActionsSetRouteLevelRouteLevel(route_level) => match route_level {
                    Some(route_level) => {
                        stmt.action_add(PolicyAction::SetRouteLevel(route_level));
                    }
                    None => {
                        stmt.action_remove(PolicyActionType::SetRouteLevel);
                    }
                },
                PolicyDefinitionStatementEntryChange::ActionsSetRoutePreference(route_pref) => match route_pref {
                    Some(route_pref) => {
                        stmt.action_add(PolicyAction::SetRoutePref(route_pref));
                    }
                    None => {
                        stmt.action_remove(PolicyActionType::SetRoutePref);
                    }
                },
                PolicyDefinitionStatementEntryChange::ActionsSetTag(tag) => match tag {
                    Some(tag) => {
                        stmt.action_add(PolicyAction::SetTag(tag.0));
                    }
                    None => {
                        stmt.action_remove(PolicyActionType::SetTag);
                    }
                },
                PolicyDefinitionStatementEntryChange::ActionsSetApplicationTag(app_tag) => match app_tag {
                    Some(app_tag) => {
                        stmt.action_add(PolicyAction::SetAppTag(app_tag.0));
                    }
                    None => {
                        stmt.action_remove(PolicyActionType::SetAppTag);
                    }
                },
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsLocalPrefValue(value) => match value {
                    Some(value) => {
                        let cond = stmt.conditions.entry(PolicyConditionType::Bgp(BgpPolicyConditionType::LocalPref)).or_insert_with(|| {
                            PolicyCondition::Bgp(BgpPolicyCondition::LocalPref {
                                value,
                                op: BgpEqOperator::Equal,
                            })
                        });
                        if let PolicyCondition::Bgp(BgpPolicyCondition::LocalPref {
                            value: cond_value, ..
                        }) = cond
                        {
                            *cond_value = value;
                        }
                    }
                    None => stmt.condition_remove(PolicyConditionType::Bgp(BgpPolicyConditionType::LocalPref)),
                },
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsLocalPrefEq(_op) => {
                    if let Some(PolicyCondition::Bgp(BgpPolicyCondition::LocalPref {
                        op: cond_op, ..
                    })) = stmt.conditions.get_mut(&PolicyConditionType::Bgp(BgpPolicyConditionType::LocalPref))
                    {
                        *cond_op = BgpEqOperator::Equal;
                    }
                }
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsLocalPrefLtOrEq(op) => {
                    if let Some(PolicyCondition::Bgp(BgpPolicyCondition::LocalPref {
                        op: cond_op, ..
                    })) = stmt.conditions.get_mut(&PolicyConditionType::Bgp(BgpPolicyConditionType::LocalPref))
                    {
                        *cond_op = match op {
                            ConfigOp::Create => BgpEqOperator::LessThanOrEqual,
                            ConfigOp::Delete => BgpEqOperator::Equal,
                        };
                    }
                }
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsLocalPrefGtOrEq(op) => {
                    if let Some(PolicyCondition::Bgp(BgpPolicyCondition::LocalPref {
                        op: cond_op, ..
                    })) = stmt.conditions.get_mut(&PolicyConditionType::Bgp(BgpPolicyConditionType::LocalPref))
                    {
                        *cond_op = match op {
                            ConfigOp::Create => BgpEqOperator::GreaterThanOrEqual,
                            ConfigOp::Delete => BgpEqOperator::Equal,
                        };
                    }
                }
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsMedValue(value) => match value {
                    Some(value) => {
                        let cond = stmt.conditions.entry(PolicyConditionType::Bgp(BgpPolicyConditionType::Med)).or_insert_with(|| {
                            PolicyCondition::Bgp(BgpPolicyCondition::Med {
                                value,
                                op: BgpEqOperator::Equal,
                            })
                        });
                        if let PolicyCondition::Bgp(BgpPolicyCondition::Med {
                            value: cond_value, ..
                        }) = cond
                        {
                            *cond_value = value;
                        }
                    }
                    None => stmt.condition_remove(PolicyConditionType::Bgp(BgpPolicyConditionType::Med)),
                },
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsMedEq(_op) => {
                    if let Some(PolicyCondition::Bgp(BgpPolicyCondition::Med {
                        op: cond_op, ..
                    })) = stmt.conditions.get_mut(&PolicyConditionType::Bgp(BgpPolicyConditionType::Med))
                    {
                        *cond_op = BgpEqOperator::Equal;
                    }
                }
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsMedLtOrEq(op) => {
                    if let Some(PolicyCondition::Bgp(BgpPolicyCondition::Med {
                        op: cond_op, ..
                    })) = stmt.conditions.get_mut(&PolicyConditionType::Bgp(BgpPolicyConditionType::Med))
                    {
                        *cond_op = match op {
                            ConfigOp::Create => BgpEqOperator::LessThanOrEqual,
                            ConfigOp::Delete => BgpEqOperator::Equal,
                        };
                    }
                }
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsMedGtOrEq(op) => {
                    if let Some(PolicyCondition::Bgp(BgpPolicyCondition::Med {
                        op: cond_op, ..
                    })) = stmt.conditions.get_mut(&PolicyConditionType::Bgp(BgpPolicyConditionType::Med))
                    {
                        *cond_op = match op {
                            ConfigOp::Create => BgpEqOperator::GreaterThanOrEqual,
                            ConfigOp::Delete => BgpEqOperator::Equal,
                        };
                    }
                }
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsCommunityCountCommunityCount(value) => match value {
                    Some(value) => {
                        let cond = stmt.conditions.entry(PolicyConditionType::Bgp(BgpPolicyConditionType::CommCount)).or_insert_with(|| {
                            PolicyCondition::Bgp(BgpPolicyCondition::CommCount {
                                value,
                                op: BgpEqOperator::Equal,
                            })
                        });
                        if let PolicyCondition::Bgp(BgpPolicyCondition::CommCount {
                            value: cond_value, ..
                        }) = cond
                        {
                            *cond_value = value;
                        }
                    }
                    None => stmt.condition_remove(PolicyConditionType::Bgp(BgpPolicyConditionType::CommCount)),
                },
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsCommunityCountEq(_op) => {
                    if let Some(PolicyCondition::Bgp(BgpPolicyCondition::CommCount {
                        op: cond_op, ..
                    })) = stmt.conditions.get_mut(&PolicyConditionType::Bgp(BgpPolicyConditionType::CommCount))
                    {
                        *cond_op = BgpEqOperator::Equal;
                    }
                }
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsCommunityCountLtOrEq(op) => {
                    if let Some(PolicyCondition::Bgp(BgpPolicyCondition::CommCount {
                        op: cond_op, ..
                    })) = stmt.conditions.get_mut(&PolicyConditionType::Bgp(BgpPolicyConditionType::CommCount))
                    {
                        *cond_op = match op {
                            ConfigOp::Create => BgpEqOperator::LessThanOrEqual,
                            ConfigOp::Delete => BgpEqOperator::Equal,
                        };
                    }
                }
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsCommunityCountGtOrEq(op) => {
                    if let Some(PolicyCondition::Bgp(BgpPolicyCondition::CommCount {
                        op: cond_op, ..
                    })) = stmt.conditions.get_mut(&PolicyConditionType::Bgp(BgpPolicyConditionType::CommCount))
                    {
                        *cond_op = match op {
                            ConfigOp::Create => BgpEqOperator::GreaterThanOrEqual,
                            ConfigOp::Delete => BgpEqOperator::Equal,
                        };
                    }
                }
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsAsPathLengthAsPathLength(value) => match value {
                    Some(value) => {
                        let cond = stmt.conditions.entry(PolicyConditionType::Bgp(BgpPolicyConditionType::AsPathLen)).or_insert_with(|| {
                            PolicyCondition::Bgp(BgpPolicyCondition::AsPathLen {
                                value,
                                op: BgpEqOperator::Equal,
                            })
                        });
                        if let PolicyCondition::Bgp(BgpPolicyCondition::AsPathLen {
                            value: cond_value, ..
                        }) = cond
                        {
                            *cond_value = value;
                        }
                    }
                    None => stmt.condition_remove(PolicyConditionType::Bgp(BgpPolicyConditionType::AsPathLen)),
                },
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsAsPathLengthEq(_op) => {
                    if let Some(PolicyCondition::Bgp(BgpPolicyCondition::AsPathLen {
                        op: cond_op, ..
                    })) = stmt.conditions.get_mut(&PolicyConditionType::Bgp(BgpPolicyConditionType::AsPathLen))
                    {
                        *cond_op = BgpEqOperator::Equal;
                    }
                }
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsAsPathLengthLtOrEq(op) => {
                    if let Some(PolicyCondition::Bgp(BgpPolicyCondition::AsPathLen {
                        op: cond_op, ..
                    })) = stmt.conditions.get_mut(&PolicyConditionType::Bgp(BgpPolicyConditionType::AsPathLen))
                    {
                        *cond_op = match op {
                            ConfigOp::Create => BgpEqOperator::LessThanOrEqual,
                            ConfigOp::Delete => BgpEqOperator::Equal,
                        };
                    }
                }
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsAsPathLengthGtOrEq(op) => {
                    if let Some(PolicyCondition::Bgp(BgpPolicyCondition::AsPathLen {
                        op: cond_op, ..
                    })) = stmt.conditions.get_mut(&PolicyConditionType::Bgp(BgpPolicyConditionType::AsPathLen))
                    {
                        *cond_op = match op {
                            ConfigOp::Create => BgpEqOperator::GreaterThanOrEqual,
                            ConfigOp::Delete => BgpEqOperator::Equal,
                        };
                    }
                }
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsOriginEq(origin) => match origin {
                    Some(origin) => stmt.condition_add(PolicyCondition::Bgp(BgpPolicyCondition::Origin(origin))),
                    None => stmt.condition_remove(PolicyConditionType::Bgp(BgpPolicyConditionType::Origin)),
                },
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsRouteType(route_type) => match route_type {
                    Some(route_type) => stmt.condition_add(PolicyCondition::Bgp(BgpPolicyCondition::RouteType(route_type))),
                    None => stmt.condition_remove(PolicyConditionType::Bgp(BgpPolicyConditionType::RouteType)),
                },
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsMatchAfiSafiAfiSafiIn(op, afi_safi) => {
                    let cond_type = PolicyConditionType::Bgp(BgpPolicyConditionType::MatchAfiSafi);
                    match op {
                        ConfigOp::Create => {
                            if let PolicyCondition::Bgp(BgpPolicyCondition::MatchAfiSafi {
                                values, ..
                            }) = stmt.conditions.entry(cond_type).or_insert_with(|| {
                                PolicyCondition::Bgp(BgpPolicyCondition::MatchAfiSafi {
                                    values: BTreeSet::new(),
                                    match_type: MatchSetRestrictedType::Any,
                                })
                            }) {
                                values.insert(afi_safi);
                            }
                        }
                        ConfigOp::Delete => {
                            if let btree_map::Entry::Occupied(mut entry) = stmt.conditions.entry(cond_type)
                                && let PolicyCondition::Bgp(BgpPolicyCondition::MatchAfiSafi {
                                    values, ..
                                }) = entry.get_mut()
                            {
                                values.remove(&afi_safi);
                                if values.is_empty() {
                                    entry.remove();
                                }
                            }
                        }
                    }
                }
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsMatchNeighborNeighborEq(op, addr) => {
                    let cond_type = PolicyConditionType::Bgp(BgpPolicyConditionType::MatchNeighbor);
                    match op {
                        ConfigOp::Create => {
                            if let PolicyCondition::Bgp(BgpPolicyCondition::MatchNeighbor {
                                value, ..
                            }) = stmt.conditions.entry(cond_type).or_insert_with(|| {
                                PolicyCondition::Bgp(BgpPolicyCondition::MatchNeighbor {
                                    value: BTreeSet::new(),
                                    match_type: MatchSetRestrictedType::Any,
                                })
                            }) {
                                value.insert(addr);
                            }
                        }
                        ConfigOp::Delete => {
                            if let btree_map::Entry::Occupied(mut entry) = stmt.conditions.entry(cond_type)
                                && let PolicyCondition::Bgp(BgpPolicyCondition::MatchNeighbor {
                                    value, ..
                                }) = entry.get_mut()
                            {
                                value.remove(&addr);
                                if value.is_empty() {
                                    entry.remove();
                                }
                            }
                        }
                    }
                }
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsMatchAfiSafiMatchSetOptions(options) => {
                    if let Some(PolicyCondition::Bgp(BgpPolicyCondition::MatchAfiSafi {
                        match_type, ..
                    })) = stmt.conditions.get_mut(&PolicyConditionType::Bgp(BgpPolicyConditionType::MatchAfiSafi))
                    {
                        *match_type = options.unwrap_or(MatchSetRestrictedType::Any);
                    }
                }
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsMatchNeighborMatchSetOptions(options) => {
                    if let Some(PolicyCondition::Bgp(BgpPolicyCondition::MatchNeighbor {
                        match_type, ..
                    })) = stmt.conditions.get_mut(&PolicyConditionType::Bgp(BgpPolicyConditionType::MatchNeighbor))
                    {
                        *match_type = options.unwrap_or(MatchSetRestrictedType::Any);
                    }
                }
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsMatchCommunitySetCommunitySet(set) => match set {
                    Some(set) => {
                        let cond = stmt.conditions.entry(PolicyConditionType::Bgp(BgpPolicyConditionType::MatchCommSet)).or_insert_with(|| {
                            PolicyCondition::Bgp(BgpPolicyCondition::MatchCommSet {
                                value: set.clone(),
                                match_type: MatchSetType::Any,
                            })
                        });
                        if let PolicyCondition::Bgp(BgpPolicyCondition::MatchCommSet {
                            value, ..
                        }) = cond
                        {
                            *value = set;
                        }
                    }
                    None => stmt.condition_remove(PolicyConditionType::Bgp(BgpPolicyConditionType::MatchCommSet)),
                },
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsMatchCommunitySetMatchSetOptions(options) => {
                    if let Some(PolicyCondition::Bgp(BgpPolicyCondition::MatchCommSet {
                        match_type, ..
                    })) = stmt.conditions.get_mut(&PolicyConditionType::Bgp(BgpPolicyConditionType::MatchCommSet))
                    {
                        *match_type = options.unwrap_or(MatchSetType::Any);
                    }
                }
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsMatchExtCommunitySetExtCommunitySet(set) => match set {
                    Some(set) => {
                        let cond = stmt.conditions.entry(PolicyConditionType::Bgp(BgpPolicyConditionType::MatchExtCommSet)).or_insert_with(|| {
                            PolicyCondition::Bgp(BgpPolicyCondition::MatchExtCommSet {
                                value: set.clone(),
                                match_type: MatchSetType::Any,
                            })
                        });
                        if let PolicyCondition::Bgp(BgpPolicyCondition::MatchExtCommSet {
                            value, ..
                        }) = cond
                        {
                            *value = set;
                        }
                    }
                    None => stmt.condition_remove(PolicyConditionType::Bgp(BgpPolicyConditionType::MatchExtCommSet)),
                },
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsMatchExtCommunitySetMatchSetOptions(options) => {
                    if let Some(PolicyCondition::Bgp(BgpPolicyCondition::MatchExtCommSet {
                        match_type, ..
                    })) = stmt.conditions.get_mut(&PolicyConditionType::Bgp(BgpPolicyConditionType::MatchExtCommSet))
                    {
                        *match_type = options.unwrap_or(MatchSetType::Any);
                    }
                }
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsMatchIpv6ExtCommunitySetIpv6ExtCommunitySet(set) => match set {
                    Some(set) => {
                        let cond = stmt.conditions.entry(PolicyConditionType::Bgp(BgpPolicyConditionType::MatchExtv6CommSet)).or_insert_with(|| {
                            PolicyCondition::Bgp(BgpPolicyCondition::MatchExtv6CommSet {
                                value: set.clone(),
                                match_type: MatchSetType::Any,
                            })
                        });
                        if let PolicyCondition::Bgp(BgpPolicyCondition::MatchExtv6CommSet {
                            value, ..
                        }) = cond
                        {
                            *value = set;
                        }
                    }
                    None => stmt.condition_remove(PolicyConditionType::Bgp(BgpPolicyConditionType::MatchExtv6CommSet)),
                },
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsMatchIpv6ExtCommunitySetMatchSetOptions(options) => {
                    if let Some(PolicyCondition::Bgp(BgpPolicyCondition::MatchExtv6CommSet {
                        match_type, ..
                    })) = stmt.conditions.get_mut(&PolicyConditionType::Bgp(BgpPolicyConditionType::MatchExtv6CommSet))
                    {
                        *match_type = options.unwrap_or(MatchSetType::Any);
                    }
                }
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsMatchLargeCommunitySetLargeCommunitySet(set) => match set {
                    Some(set) => {
                        let cond = stmt.conditions.entry(PolicyConditionType::Bgp(BgpPolicyConditionType::MatchLargeCommSet)).or_insert_with(|| {
                            PolicyCondition::Bgp(BgpPolicyCondition::MatchLargeCommSet {
                                value: set.clone(),
                                match_type: MatchSetType::Any,
                            })
                        });
                        if let PolicyCondition::Bgp(BgpPolicyCondition::MatchLargeCommSet {
                            value, ..
                        }) = cond
                        {
                            *value = set;
                        }
                    }
                    None => stmt.condition_remove(PolicyConditionType::Bgp(BgpPolicyConditionType::MatchLargeCommSet)),
                },
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsMatchLargeCommunitySetMatchSetOptions(options) => {
                    if let Some(PolicyCondition::Bgp(BgpPolicyCondition::MatchLargeCommSet {
                        match_type, ..
                    })) = stmt.conditions.get_mut(&PolicyConditionType::Bgp(BgpPolicyConditionType::MatchLargeCommSet))
                    {
                        *match_type = options.unwrap_or(MatchSetType::Any);
                    }
                }
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsMatchAsPathSetAsPathSet(set) => match set {
                    Some(set) => {
                        let cond = stmt.conditions.entry(PolicyConditionType::Bgp(BgpPolicyConditionType::MatchAsPathSet)).or_insert_with(|| {
                            PolicyCondition::Bgp(BgpPolicyCondition::MatchAsPathSet {
                                value: set.clone(),
                                match_type: MatchSetType::Any,
                            })
                        });
                        if let PolicyCondition::Bgp(BgpPolicyCondition::MatchAsPathSet {
                            value, ..
                        }) = cond
                        {
                            *value = set;
                        }
                    }
                    None => stmt.condition_remove(PolicyConditionType::Bgp(BgpPolicyConditionType::MatchAsPathSet)),
                },
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsMatchAsPathSetMatchSetOptions(options) => {
                    if let Some(PolicyCondition::Bgp(BgpPolicyCondition::MatchAsPathSet {
                        match_type, ..
                    })) = stmt.conditions.get_mut(&PolicyConditionType::Bgp(BgpPolicyConditionType::MatchAsPathSet))
                    {
                        *match_type = options.unwrap_or(MatchSetType::Any);
                    }
                }
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsMatchNextHopSetNextHopSet(set) => match set {
                    Some(set) => {
                        let cond = stmt.conditions.entry(PolicyConditionType::Bgp(BgpPolicyConditionType::MatchNexthopSet)).or_insert_with(|| {
                            PolicyCondition::Bgp(BgpPolicyCondition::MatchNexthopSet {
                                value: set.clone(),
                                match_type: MatchSetRestrictedType::Any,
                            })
                        });
                        if let PolicyCondition::Bgp(BgpPolicyCondition::MatchNexthopSet {
                            value, ..
                        }) = cond
                        {
                            *value = set;
                        }
                    }
                    None => stmt.condition_remove(PolicyConditionType::Bgp(BgpPolicyConditionType::MatchNexthopSet)),
                },
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsMatchNextHopSetMatchSetOptions(options) => {
                    if let Some(PolicyCondition::Bgp(BgpPolicyCondition::MatchNexthopSet {
                        match_type, ..
                    })) = stmt.conditions.get_mut(&PolicyConditionType::Bgp(BgpPolicyConditionType::MatchNexthopSet))
                    {
                        *match_type = options.unwrap_or(MatchSetRestrictedType::Any);
                    }
                }
                // TODO: implement the extended community match kinds.
                PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsMatchExtCommunitySetExtCommunityMatchKind(..)
                | PolicyDefinitionStatementEntryChange::ConditionsBgpConditionsMatchIpv6ExtCommunitySetIpv6ExtCommunityMatchKind(..) => (),
                PolicyDefinitionStatementEntryChange::ActionsSetMetricMetricModification(mod_type) => match mod_type {
                    Some(mod_type) => {
                        let action = stmt.actions.entry(PolicyActionType::SetMetric).or_insert_with(|| PolicyAction::SetMetric {
                            value: 0,
                            mod_type,
                        });
                        if let PolicyAction::SetMetric {
                            mod_type: action_mod_type, ..
                        } = action
                        {
                            *action_mod_type = mod_type;
                        }
                    }
                    None => {
                        if let Some(PolicyAction::SetMetric {
                            mod_type, ..
                        }) = stmt.actions.get_mut(&PolicyActionType::SetMetric)
                        {
                            *mod_type = MetricModification::Set;
                        }
                    }
                },
                PolicyDefinitionStatementEntryChange::ActionsSetMetricMetric(metric) => match metric {
                    Some(metric) => {
                        let action = stmt.actions.entry(PolicyActionType::SetMetric).or_insert_with(|| PolicyAction::SetMetric {
                            value: metric,
                            mod_type: MetricModification::Set,
                        });
                        if let PolicyAction::SetMetric {
                            value, ..
                        } = action
                        {
                            *value = metric;
                        }
                    }
                    None => {
                        stmt.action_remove(PolicyActionType::SetMetric);
                    }
                },
                PolicyDefinitionStatementEntryChange::ActionsBgpActionsSetRouteOrigin(origin) => match origin {
                    Some(origin) => stmt.action_add(PolicyAction::Bgp(BgpPolicyAction::SetRouteOrigin(origin))),
                    None => stmt.action_remove(PolicyActionType::Bgp(BgpPolicyActionType::SetRouteOrigin)),
                },
                PolicyDefinitionStatementEntryChange::ActionsBgpActionsSetLocalPref(local_pref) => match local_pref {
                    Some(local_pref) => stmt.action_add(PolicyAction::Bgp(BgpPolicyAction::SetLocalPref(local_pref))),
                    None => stmt.action_remove(PolicyActionType::Bgp(BgpPolicyActionType::SetLocalPref)),
                },
                PolicyDefinitionStatementEntryChange::ActionsBgpActionsSetNextHop(next_hop) => match next_hop {
                    Some(next_hop) => stmt.action_add(PolicyAction::Bgp(BgpPolicyAction::SetNexthop(next_hop))),
                    None => stmt.action_remove(PolicyActionType::Bgp(BgpPolicyActionType::SetNexthop)),
                },
                PolicyDefinitionStatementEntryChange::ActionsBgpActionsSetMed(med) => match med {
                    Some(med) => stmt.action_add(PolicyAction::Bgp(BgpPolicyAction::SetMed(med))),
                    None => stmt.action_remove(PolicyActionType::Bgp(BgpPolicyActionType::SetMed)),
                },
                PolicyDefinitionStatementEntryChange::ActionsBgpActionsSetAsPathPrependRepeatN(repeat_n) => {
                    let action_type = PolicyActionType::Bgp(BgpPolicyActionType::SetAsPathPrepent);
                    match repeat_n {
                        Some(repeat_n) => {
                            let action = stmt.actions.entry(action_type).or_insert_with(|| {
                                PolicyAction::Bgp(BgpPolicyAction::SetAsPathPrepent {
                                    asn: 0,
                                    repeat: None,
                                })
                            });
                            if let PolicyAction::Bgp(BgpPolicyAction::SetAsPathPrepent {
                                repeat, ..
                            }) = action
                            {
                                *repeat = Some(repeat_n);
                            }
                        }
                        None => {
                            if let Some(PolicyAction::Bgp(BgpPolicyAction::SetAsPathPrepent {
                                repeat, ..
                            })) = stmt.actions.get_mut(&action_type)
                            {
                                *repeat = None;
                            }
                        }
                    }
                }
                PolicyDefinitionStatementEntryChange::ActionsBgpActionsSetAsPathPrependAsn(op, asn) => {
                    let action_type = PolicyActionType::Bgp(BgpPolicyActionType::SetAsPathPrepent);
                    match op {
                        ConfigOp::Create => {
                            let action = stmt.actions.entry(action_type).or_insert_with(|| {
                                PolicyAction::Bgp(BgpPolicyAction::SetAsPathPrepent {
                                    asn,
                                    repeat: None,
                                })
                            });
                            if let PolicyAction::Bgp(BgpPolicyAction::SetAsPathPrepent {
                                asn: action_asn, ..
                            }) = action
                            {
                                *action_asn = asn;
                            }
                        }
                        ConfigOp::Delete => {
                            if let btree_map::Entry::Occupied(entry) = stmt.actions.entry(action_type)
                                && let PolicyAction::Bgp(BgpPolicyAction::SetAsPathPrepent {
                                    asn: action_asn, ..
                                }) = entry.get()
                                && *action_asn == asn
                            {
                                entry.remove();
                            }
                        }
                    }
                }
                PolicyDefinitionStatementEntryChange::ActionsBgpActionsSetCommunityOptions(options) => match options {
                    Some(options) => {
                        let action = stmt.actions.entry(PolicyActionType::Bgp(BgpPolicyActionType::SetComm)).or_insert_with(|| {
                            PolicyAction::Bgp(BgpPolicyAction::SetComm {
                                options: BgpSetCommOptions::Add,
                                method: BgpSetCommMethod::Inline(BTreeSet::new()),
                            })
                        });
                        if let PolicyAction::Bgp(BgpPolicyAction::SetComm {
                            options: action_options, ..
                        }) = action
                        {
                            *action_options = options;
                        }
                    }
                    None => {
                        if let Some(PolicyAction::Bgp(BgpPolicyAction::SetComm {
                            options, ..
                        })) = stmt.actions.get_mut(&PolicyActionType::Bgp(BgpPolicyActionType::SetComm))
                        {
                            *options = BgpSetCommOptions::Add;
                        }
                    }
                },
                PolicyDefinitionStatementEntryChange::ActionsBgpActionsSetCommunityCommunities(op, comm) => {
                    let action = match op {
                        ConfigOp::Create => Some(stmt.actions.entry(PolicyActionType::Bgp(BgpPolicyActionType::SetComm)).or_insert_with(|| {
                            PolicyAction::Bgp(BgpPolicyAction::SetComm {
                                options: BgpSetCommOptions::Add,
                                method: BgpSetCommMethod::Inline(BTreeSet::new()),
                            })
                        })),
                        ConfigOp::Delete => stmt.actions.get_mut(&PolicyActionType::Bgp(BgpPolicyActionType::SetComm)),
                    };
                    if let Some(PolicyAction::Bgp(BgpPolicyAction::SetComm {
                        method, ..
                    })) = action
                    {
                        apply_bgp_action_comm_member(method, op, comm);
                    }
                }
                PolicyDefinitionStatementEntryChange::ActionsBgpActionsSetCommunityCommunitySetRef(set_ref) => match set_ref {
                    Some(set_ref) => {
                        let action = stmt.actions.entry(PolicyActionType::Bgp(BgpPolicyActionType::SetComm)).or_insert_with(|| {
                            PolicyAction::Bgp(BgpPolicyAction::SetComm {
                                options: BgpSetCommOptions::Add,
                                method: BgpSetCommMethod::Inline(BTreeSet::new()),
                            })
                        });
                        if let PolicyAction::Bgp(BgpPolicyAction::SetComm {
                            method, ..
                        }) = action
                        {
                            *method = BgpSetCommMethod::Reference(set_ref);
                        }
                    }
                    None => {
                        if let Some(PolicyAction::Bgp(BgpPolicyAction::SetComm {
                            method: BgpSetCommMethod::Reference(..), ..
                        })) = stmt.actions.get(&PolicyActionType::Bgp(BgpPolicyActionType::SetComm))
                        {
                            stmt.actions.remove(&PolicyActionType::Bgp(BgpPolicyActionType::SetComm));
                        }
                    }
                },
                PolicyDefinitionStatementEntryChange::ActionsBgpActionsSetExtCommunityOptions(options) => match options {
                    Some(options) => {
                        let action = stmt.actions.entry(PolicyActionType::Bgp(BgpPolicyActionType::SetExtComm)).or_insert_with(|| {
                            PolicyAction::Bgp(BgpPolicyAction::SetExtComm {
                                options: BgpSetCommOptions::Add,
                                method: BgpSetCommMethod::Inline(BTreeSet::new()),
                            })
                        });
                        if let PolicyAction::Bgp(BgpPolicyAction::SetExtComm {
                            options: action_options, ..
                        }) = action
                        {
                            *action_options = options;
                        }
                    }
                    None => {
                        if let Some(PolicyAction::Bgp(BgpPolicyAction::SetExtComm {
                            options, ..
                        })) = stmt.actions.get_mut(&PolicyActionType::Bgp(BgpPolicyActionType::SetExtComm))
                        {
                            *options = BgpSetCommOptions::Add;
                        }
                    }
                },
                PolicyDefinitionStatementEntryChange::ActionsBgpActionsSetExtCommunityCommunities(op, comm) => {
                    let action = match op {
                        ConfigOp::Create => Some(stmt.actions.entry(PolicyActionType::Bgp(BgpPolicyActionType::SetExtComm)).or_insert_with(|| {
                            PolicyAction::Bgp(BgpPolicyAction::SetExtComm {
                                options: BgpSetCommOptions::Add,
                                method: BgpSetCommMethod::Inline(BTreeSet::new()),
                            })
                        })),
                        ConfigOp::Delete => stmt.actions.get_mut(&PolicyActionType::Bgp(BgpPolicyActionType::SetExtComm)),
                    };
                    if let Some(PolicyAction::Bgp(BgpPolicyAction::SetExtComm {
                        method, ..
                    })) = action
                    {
                        apply_bgp_action_comm_member(method, op, comm);
                    }
                }
                PolicyDefinitionStatementEntryChange::ActionsBgpActionsSetExtCommunityExtCommunitySetRef(set_ref) => match set_ref {
                    Some(set_ref) => {
                        let action = stmt.actions.entry(PolicyActionType::Bgp(BgpPolicyActionType::SetExtComm)).or_insert_with(|| {
                            PolicyAction::Bgp(BgpPolicyAction::SetExtComm {
                                options: BgpSetCommOptions::Add,
                                method: BgpSetCommMethod::Inline(BTreeSet::new()),
                            })
                        });
                        if let PolicyAction::Bgp(BgpPolicyAction::SetExtComm {
                            method, ..
                        }) = action
                        {
                            *method = BgpSetCommMethod::Reference(set_ref);
                        }
                    }
                    None => {
                        if let Some(PolicyAction::Bgp(BgpPolicyAction::SetExtComm {
                            method: BgpSetCommMethod::Reference(..), ..
                        })) = stmt.actions.get(&PolicyActionType::Bgp(BgpPolicyActionType::SetExtComm))
                        {
                            stmt.actions.remove(&PolicyActionType::Bgp(BgpPolicyActionType::SetExtComm));
                        }
                    }
                },
                PolicyDefinitionStatementEntryChange::ActionsBgpActionsSetIpv6ExtCommunityOptions(options) => match options {
                    Some(options) => {
                        let action = stmt.actions.entry(PolicyActionType::Bgp(BgpPolicyActionType::SetExtv6Comm)).or_insert_with(|| {
                            PolicyAction::Bgp(BgpPolicyAction::SetExtv6Comm {
                                options: BgpSetCommOptions::Add,
                                method: BgpSetCommMethod::Inline(BTreeSet::new()),
                            })
                        });
                        if let PolicyAction::Bgp(BgpPolicyAction::SetExtv6Comm {
                            options: action_options, ..
                        }) = action
                        {
                            *action_options = options;
                        }
                    }
                    None => {
                        if let Some(PolicyAction::Bgp(BgpPolicyAction::SetExtv6Comm {
                            options, ..
                        })) = stmt.actions.get_mut(&PolicyActionType::Bgp(BgpPolicyActionType::SetExtv6Comm))
                        {
                            *options = BgpSetCommOptions::Add;
                        }
                    }
                },
                PolicyDefinitionStatementEntryChange::ActionsBgpActionsSetIpv6ExtCommunityCommunities(op, comm) => {
                    let action = match op {
                        ConfigOp::Create => Some(stmt.actions.entry(PolicyActionType::Bgp(BgpPolicyActionType::SetExtv6Comm)).or_insert_with(|| {
                            PolicyAction::Bgp(BgpPolicyAction::SetExtv6Comm {
                                options: BgpSetCommOptions::Add,
                                method: BgpSetCommMethod::Inline(BTreeSet::new()),
                            })
                        })),
                        ConfigOp::Delete => stmt.actions.get_mut(&PolicyActionType::Bgp(BgpPolicyActionType::SetExtv6Comm)),
                    };
                    if let Some(PolicyAction::Bgp(BgpPolicyAction::SetExtv6Comm {
                        method, ..
                    })) = action
                    {
                        apply_bgp_action_comm_member(method, op, comm);
                    }
                }
                PolicyDefinitionStatementEntryChange::ActionsBgpActionsSetIpv6ExtCommunityIpv6ExtCommunitySetRef(set_ref) => match set_ref {
                    Some(set_ref) => {
                        let action = stmt.actions.entry(PolicyActionType::Bgp(BgpPolicyActionType::SetExtv6Comm)).or_insert_with(|| {
                            PolicyAction::Bgp(BgpPolicyAction::SetExtv6Comm {
                                options: BgpSetCommOptions::Add,
                                method: BgpSetCommMethod::Inline(BTreeSet::new()),
                            })
                        });
                        if let PolicyAction::Bgp(BgpPolicyAction::SetExtv6Comm {
                            method, ..
                        }) = action
                        {
                            *method = BgpSetCommMethod::Reference(set_ref);
                        }
                    }
                    None => {
                        if let Some(PolicyAction::Bgp(BgpPolicyAction::SetExtv6Comm {
                            method: BgpSetCommMethod::Reference(..), ..
                        })) = stmt.actions.get(&PolicyActionType::Bgp(BgpPolicyActionType::SetExtv6Comm))
                        {
                            stmt.actions.remove(&PolicyActionType::Bgp(BgpPolicyActionType::SetExtv6Comm));
                        }
                    }
                },
                PolicyDefinitionStatementEntryChange::ActionsBgpActionsSetLargeCommunityOptions(options) => match options {
                    Some(options) => {
                        let action = stmt.actions.entry(PolicyActionType::Bgp(BgpPolicyActionType::SetLargeComm)).or_insert_with(|| {
                            PolicyAction::Bgp(BgpPolicyAction::SetLargeComm {
                                options: BgpSetCommOptions::Add,
                                method: BgpSetCommMethod::Inline(BTreeSet::new()),
                            })
                        });
                        if let PolicyAction::Bgp(BgpPolicyAction::SetLargeComm {
                            options: action_options, ..
                        }) = action
                        {
                            *action_options = options;
                        }
                    }
                    None => {
                        if let Some(PolicyAction::Bgp(BgpPolicyAction::SetLargeComm {
                            options, ..
                        })) = stmt.actions.get_mut(&PolicyActionType::Bgp(BgpPolicyActionType::SetLargeComm))
                        {
                            *options = BgpSetCommOptions::Add;
                        }
                    }
                },
                PolicyDefinitionStatementEntryChange::ActionsBgpActionsSetLargeCommunityCommunities(op, comm) => {
                    let action = match op {
                        ConfigOp::Create => Some(stmt.actions.entry(PolicyActionType::Bgp(BgpPolicyActionType::SetLargeComm)).or_insert_with(|| {
                            PolicyAction::Bgp(BgpPolicyAction::SetLargeComm {
                                options: BgpSetCommOptions::Add,
                                method: BgpSetCommMethod::Inline(BTreeSet::new()),
                            })
                        })),
                        ConfigOp::Delete => stmt.actions.get_mut(&PolicyActionType::Bgp(BgpPolicyActionType::SetLargeComm)),
                    };
                    if let Some(PolicyAction::Bgp(BgpPolicyAction::SetLargeComm {
                        method, ..
                    })) = action
                    {
                        apply_bgp_action_comm_member(method, op, comm);
                    }
                }
                PolicyDefinitionStatementEntryChange::ActionsBgpActionsSetLargeCommunityLargeCommunitySetRef(set_ref) => match set_ref {
                    Some(set_ref) => {
                        let action = stmt.actions.entry(PolicyActionType::Bgp(BgpPolicyActionType::SetLargeComm)).or_insert_with(|| {
                            PolicyAction::Bgp(BgpPolicyAction::SetLargeComm {
                                options: BgpSetCommOptions::Add,
                                method: BgpSetCommMethod::Inline(BTreeSet::new()),
                            })
                        });
                        if let PolicyAction::Bgp(BgpPolicyAction::SetLargeComm {
                            method, ..
                        }) = action
                        {
                            *method = BgpSetCommMethod::Reference(set_ref);
                        }
                    }
                    None => {
                        if let Some(PolicyAction::Bgp(BgpPolicyAction::SetLargeComm {
                            method: BgpSetCommMethod::Reference(..), ..
                        })) = stmt.actions.get(&PolicyActionType::Bgp(BgpPolicyActionType::SetLargeComm))
                        {
                            stmt.actions.remove(&PolicyActionType::Bgp(BgpPolicyActionType::SetLargeComm));
                        }
                    }
                },
            }
        }
    }

    Ok(())
}

fn apply_bgp_action_comm_member<T: Eq + Ord>(method: &mut BgpSetCommMethod<T>, op: ConfigOp, member: T) {
    match op {
        ConfigOp::Create => match method {
            BgpSetCommMethod::Inline(comms) => {
                comms.insert(member);
            }
            method => *method = BgpSetCommMethod::Inline(BTreeSet::from([member])),
        },
        ConfigOp::Delete => {
            if let BgpSetCommMethod::Inline(comms) = method {
                comms.remove(&member);
            }
        }
    }
}

fn process_event(master: &mut Master, event: Event) {
    match event {
        Event::MatchSetsUpdate => {
            // Create a reference-counted copy of the policy match sets to
            // be shared among all protocol instances.
            let match_sets = Arc::new(master.match_sets.clone());

            // Notify protocols that the policy match sets have been
            // updated.
            master.ibus_tx.policy_match_sets_upd(match_sets);
        }
        Event::PolicyChange(name) => {
            let policy = master.policies.get_mut(&name).unwrap();

            // Create a reference-counted copy of the policy definition to
            // be shared among all protocol instances.
            let policy = Arc::new(policy.clone());

            // Notify protocols that the policy has been updated.
            master.ibus_tx.policy_upd(policy);
        }
        Event::PolicyDelete(name) => {
            // Notify protocols that the policy definition has been deleted.
            master.ibus_tx.policy_del(name);
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
