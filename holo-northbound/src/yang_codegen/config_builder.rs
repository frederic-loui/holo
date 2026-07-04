//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::HashMap;

use convert_case::{Case, Casing};
use yang5::context::Context;
use yang5::schema::{
    DataValueType, SchemaNode, SchemaNodeKind, SchemaPathFormat,
};

use crate::configuration::ChangeOp;
use crate::yang_codegen::SchemaNodeCodegenExt;
use crate::yang_codegen::code_writer::{CodeWriter, emit};
use crate::yang_codegen::types::leaf_spec;

// Generated type names for a configuration list scope.
struct ScopeInfo {
    // Base name shared by the scope's generated types (e.g. "Interface"
    // yields InterfaceKeys, InterfaceChange and InterfaceEntryChange).
    type_base: String,
    // Whether the scope has changes other than the creation and deletion of
    // its own list entries.
    has_entry_changes: bool,
}

// Code generation context for a crate's configuration changes.
struct GenCtx<'a> {
    modules: &'a [&'a str],
    path_root: Option<&'a str>,
    // All nodes that produce configuration changes, in schema order.
    change_nodes: Vec<SchemaNode<'a>>,
    // Configuration list scopes, keyed by schema path.
    scopes: HashMap<String, ScopeInfo>,
    // Variant name of each change node within its scope's change enum,
    // keyed by schema path.
    variants: HashMap<String, String>,
}

// Rust payload type and match arms for a change enum variant.
struct VariantOps {
    payload: String,
    // (ChangeOp pattern, payload expression) pairs. The payload expression
    // may reference `value`, the leaf's canonical value string.
    arms: Vec<(&'static str, String)>,
}

// ===== impl ScopeInfo =====

impl ScopeInfo {
    fn keys_type(&self) -> String {
        format!("{}Keys", self.type_base)
    }

    fn change_type(&self) -> String {
        format!("{}Change", self.type_base)
    }

    fn entry_change_type(&self) -> String {
        format!("{}EntryChange", self.type_base)
    }

    fn keys_fn(&self) -> String {
        format!("{}_keys", self.type_base.to_case(Case::Snake))
    }
}

// ===== impl GenCtx =====

impl<'a> GenCtx<'a> {
    fn new(
        yang_ctx: &'a Context,
        modules: &'a [&'a str],
        path_root: Option<&'a str>,
    ) -> Self {
        let change_nodes = yang_ctx
            .traverse()
            .filter(|snode| is_change_node(snode, modules, path_root))
            .collect::<Vec<_>>();

        // Pascal-case segment chain of each change node.
        let chains = change_nodes.iter().map(segment_chain).collect::<Vec<_>>();
        let chain_lens: HashMap<String, usize> = change_nodes
            .iter()
            .zip(&chains)
            .map(|(snode, chain)| {
                (snode.path(SchemaPathFormat::DATA), chain.segments.len())
            })
            .collect();

        // The config root is the deepest ancestor shared by all change
        // nodes; generated names are relative to it.
        let max_root_len = chains
            .iter()
            .map(|chain| chain.segments.len())
            .min()
            .unwrap_or(1)
            .saturating_sub(1);
        let mut root_len = 0;
        while root_len < max_root_len
            && chains.iter().all(|chain| {
                chain.segments[root_len] == chains[0].segments[root_len]
            })
        {
            root_len += 1;
        }

        // Compute the generated type names of all configuration list scopes.
        let mut scopes = HashMap::new();
        let mut type_bases = HashMap::new();
        for (idx, snode) in change_nodes
            .iter()
            .enumerate()
            .filter(|(_, snode)| snode.kind() == SchemaNodeKind::List)
        {
            let path = snode.path(SchemaPathFormat::DATA);
            let type_base = chains[idx].name_from(root_len);
            if let Some(other) =
                type_bases.insert(type_base.clone(), path.clone())
            {
                panic!(
                    "Duplicate generated type name {type_base}: {other} vs \
                     {path}"
                );
            }
            scopes.insert(
                path,
                ScopeInfo {
                    type_base,
                    has_entry_changes: false,
                },
            );
        }

        // A scope's entry change type must not collide with the change type of
        // a scope whose name ends in "Entry".
        for (type_base, path) in &type_bases {
            if let Some(stem) = type_base.strip_suffix("Entry")
                && let Some(other) = type_bases.get(stem)
            {
                panic!(
                    "Duplicate generated type name {type_base}Change: \
                     {other} vs {path}"
                );
            }
        }

        // Compute the variant name of each change node, relative to its
        // scope root.
        let mut variants = HashMap::new();
        let mut scope_variants: HashMap<
            Option<String>,
            HashMap<String, String>,
        > = HashMap::new();
        for (idx, snode) in change_nodes.iter().enumerate() {
            let path = snode.path(SchemaPathFormat::DATA);
            let scope = scope_parent(snode, modules, path_root)
                .map(|snode| snode.path(SchemaPathFormat::DATA));
            let start = scope
                .as_ref()
                .map(|path| chain_lens[path])
                .unwrap_or(root_len);
            let name = chains[idx].name_from(start);
            if let Some(other) = scope_variants
                .entry(scope)
                .or_default()
                .insert(name.clone(), path.clone())
            {
                panic!(
                    "Duplicate generated variant name {name}: {other} vs \
                     {path}"
                );
            }
            variants.insert(path, name);
        }

        // Flag the scopes that own changes other than their own list entry
        // creation and deletion.
        for scope in scope_variants.into_keys().flatten() {
            if let Some(info) = scopes.get_mut(&scope) {
                info.has_entry_changes = true;
            }
        }

        GenCtx {
            modules,
            path_root,
            change_nodes,
            scopes,
            variants,
        }
    }

    // Returns the nearest enclosing configuration list scope of this node.
    fn scope_parent(&self, snode: &SchemaNode<'a>) -> Option<SchemaNode<'a>> {
        scope_parent(snode, self.modules, self.path_root)
    }

    // Returns the generated info of the scope defined by the given list.
    fn scope_info(&self, snode: &SchemaNode<'_>) -> &ScopeInfo {
        &self.scopes[&snode.path(SchemaPathFormat::DATA)]
    }

    // Enum type holding the changes of an existing entry of the given scope,
    // or the root ConfigChange enum for the root scope.
    fn scope_entry_change_type(
        &self,
        scope: Option<&SchemaNode<'_>>,
    ) -> String {
        match scope {
            Some(snode) => self.scope_info(snode).entry_change_type(),
            None => "ConfigChange".to_owned(),
        }
    }

    // Variant name of the given node within its scope's change enum.
    fn variant_name(&self, snode: &SchemaNode<'_>) -> &str {
        &self.variants[&snode.path(SchemaPathFormat::DATA)]
    }

    // Configuration lists in schema order.
    fn config_lists(&self) -> impl Iterator<Item = &SchemaNode<'a>> {
        self.change_nodes
            .iter()
            .filter(|snode| snode.kind() == SchemaNodeKind::List)
    }
}

// ===== helper functions =====

// Returns true if this list node defines a configuration change scope.
fn is_config_list(
    snode: &SchemaNode<'_>,
    modules: &[&str],
    path_root: Option<&str>,
) -> bool {
    snode.kind() == SchemaNodeKind::List
        && is_change_node(snode, modules, path_root)
}

// Returns true if this node produces configuration changes.
fn is_change_node(
    snode: &SchemaNode<'_>,
    modules: &[&str],
    path_root: Option<&str>,
) -> bool {
    if !snode.is_config()
        || !snode.is_status_current()
        || !snode.in_modules(modules)
        || path_root.is_some_and(|name| !snode.has_ancestor_named(name))
    {
        return false;
    }
    [ChangeOp::Create, ChangeOp::Modify, ChangeOp::Delete]
        .iter()
        .any(|op| op.is_valid(snode))
}

// Returns the nearest enclosing configuration list scope of this node.
fn scope_parent<'a>(
    snode: &SchemaNode<'a>,
    modules: &'a [&str],
    path_root: Option<&str>,
) -> Option<SchemaNode<'a>> {
    snode
        .ancestors()
        .find(|snode| is_config_list(snode, modules, path_root))
}

// Pascal-case segment chain of a node, used to derive generated names.
//
// Names concatenate the full chain relative to the enclosing scope, except
// that wrapper containers whose name is restated by the single list they
// hold are skipped: "interfaces/interface" contributes a single "Interface"
// segment, while wrappers carrying their own meaning (as in
// "trace-options/flag") are kept.
fn segment_chain(snode: &SchemaNode<'_>) -> Chain {
    let mut nodes = snode
        .inclusive_ancestors()
        .filter(|snode| !snode.is_schema_only())
        .collect::<Vec<_>>();
    nodes.reverse();

    let mut segments = Vec::with_capacity(nodes.len());
    let mut collapsible = Vec::with_capacity(nodes.len());
    for (idx, node) in nodes.iter().enumerate() {
        segments.push(node.rust_name(Case::Pascal));
        collapsible.push(
            node.kind() == SchemaNodeKind::Container
                && node.is_np_container()
                && node.children().count() == 1
                && nodes.get(idx + 1).is_some_and(|next| {
                    next.kind() == SchemaNodeKind::List
                        && restates_wrapper(node.name(), next.name())
                }),
        );
    }
    Chain {
        segments,
        collapsible,
    }
}

// Returns true if a list name restates its wrapper container's name (e.g.
// "interface" within "interfaces", or "address-family-list" within
// "address-families"), making the wrapper redundant in generated names.
fn restates_wrapper(wrapper: &str, list: &str) -> bool {
    let mut singulars = vec![wrapper.to_owned()];
    if let Some(stem) = wrapper.strip_suffix("ies") {
        singulars.push(format!("{stem}y"));
    }
    if let Some(stem) = wrapper.strip_suffix("es") {
        singulars.push(stem.to_owned());
    }
    if let Some(stem) = wrapper.strip_suffix('s') {
        singulars.push(stem.to_owned());
    }
    singulars.iter().any(|singular| {
        list == singular || list.starts_with(&format!("{singular}-"))
    })
}

// A name chain: the full segment list plus which segments are collapsible
// wrappers.
#[derive(Clone)]
struct Chain {
    segments: Vec<String>,
    collapsible: Vec<bool>,
}

impl Chain {
    // Returns the name formed by the subchain below the given number of
    // leading segments, skipping collapsible wrappers.
    fn name_from(&self, start: usize) -> String {
        self.segments[start..]
            .iter()
            .zip(&self.collapsible[start..])
            .filter(|(_, collapsible)| !**collapsible)
            .map(|(segment, _)| segment.as_str())
            .collect()
    }
}

// Returns the generated code expression for parsing an owned leaf value from
// its canonical string representation.
fn parse_value_expr(rust_type: &str) -> String {
    match rust_type {
        "String" => "value".to_owned(),
        _ => "TryFromYang::try_from_yang(&value)\
              .ok_or(ParseError::InvalidValue(value))?"
            .to_owned(),
    }
}

// Returns the variant payload type and per-operation constructors for a
// change node, or None for list nodes (whose Create/Delete live in their own
// scope enum).
fn variant_ops(snode: &SchemaNode<'_>) -> Option<VariantOps> {
    match snode.kind() {
        SchemaNodeKind::Leaf => {
            let leaf_type = snode.leaf_type()?;
            let spec = leaf_spec(snode)?;
            // Leaves of type empty can only be created or deleted.
            if leaf_type.base_type() == DataValueType::Empty {
                return Some(VariantOps {
                    payload: "ConfigOp".to_owned(),
                    arms: vec![
                        ("ChangeOp::Create", "ConfigOp::Create".to_owned()),
                        ("ChangeOp::Delete", "ConfigOp::Delete".to_owned()),
                    ],
                });
            }
            let value = parse_value_expr(spec.rust_type);
            if ChangeOp::Delete.is_valid(snode) {
                Some(VariantOps {
                    payload: format!("Option<{}>", spec.rust_type),
                    arms: vec![
                        ("ChangeOp::Modify", format!("Some({value})")),
                        ("ChangeOp::Delete", "None".to_owned()),
                    ],
                })
            } else {
                Some(VariantOps {
                    payload: spec.rust_type.to_owned(),
                    arms: vec![("ChangeOp::Modify", value)],
                })
            }
        }
        SchemaNodeKind::LeafList => {
            let spec = leaf_spec(snode)?;
            let value = parse_value_expr(spec.rust_type);
            Some(VariantOps {
                payload: format!("ConfigOp, {}", spec.rust_type),
                arms: vec![
                    ("ChangeOp::Create", format!("ConfigOp::Create, {value}")),
                    ("ChangeOp::Delete", format!("ConfigOp::Delete, {value}")),
                ],
            })
        }
        // Presence containers.
        SchemaNodeKind::Container => Some(VariantOps {
            payload: "ConfigOp".to_owned(),
            arms: vec![
                ("ChangeOp::Create", "ConfigOp::Create".to_owned()),
                ("ChangeOp::Delete", "ConfigOp::Delete".to_owned()),
            ],
        }),
        _ => None,
    }
}

// ===== code generation =====

fn generate_keys_struct(
    w: &mut CodeWriter,
    snode: &SchemaNode<'_>,
    info: &ScopeInfo,
) -> std::fmt::Result {
    emit!(w, 0, "#[derive(Clone, Debug)]")?;
    emit!(w, 0, "pub struct {} {{", info.keys_type())?;
    for key in snode.list_keys() {
        let field_name = key.rust_name(Case::Snake);
        let spec = leaf_spec(&key).unwrap();
        emit!(w, 1, "pub {field_name}: {},", spec.rust_type)?;
    }
    emit!(w, 0, "}}")?;
    Ok(())
}

fn generate_keys_fn(
    w: &mut CodeWriter,
    snode: &SchemaNode<'_>,
    info: &ScopeInfo,
) -> std::fmt::Result {
    let path = snode.path(SchemaPathFormat::DATA);

    emit!(
        w,
        0,
        "fn {}(dnode: &DataNodeRef<'_>) -> Result<{}, ParseError> {{",
        info.keys_fn(),
        info.keys_type()
    )?;
    emit!(
        w,
        1,
        "let dnode = dnode.inclusive_ancestors().find(|dnode| \
         dnode.schema().data_path() == \"{path}\")\
         .ok_or(ParseError::ListEntryNotFound)?;"
    )?;
    emit!(w, 1, "Ok({} {{", info.keys_type())?;
    for key in snode.list_keys() {
        let field_name = key.rust_name(Case::Snake);
        let key_name = key.name();
        let spec = leaf_spec(&key).unwrap();
        let expr = match spec.rust_type {
            "String" => format!(
                "dnode.get_string_relative(\"./{key_name}\")\
                 .ok_or(ParseError::MissingListKey(\"{key_name}\"))?"
            ),
            _ => format!(
                "dnode.get_string_relative(\"./{key_name}\")\
                 .and_then(|value| TryFromYang::try_from_yang(&value))\
                 .ok_or(ParseError::InvalidListKey(\"{key_name}\"))?"
            ),
        };
        emit!(w, 2, "{field_name}: {expr},")?;
    }
    emit!(w, 1, "}})")?;
    emit!(w, 0, "}}")?;
    Ok(())
}

// Emits the change enum of a scope. List scopes get two enums: one covering
// the creation and deletion of their entries, and one covering the changes
// within an existing entry.
fn generate_change_enum(
    w: &mut CodeWriter,
    ctx: &GenCtx<'_>,
    scope: Option<&SchemaNode<'_>>,
) -> std::fmt::Result {
    let scope_path = scope.map(|scope| scope.path(SchemaPathFormat::DATA));

    if let Some(scope) = scope {
        let info = ctx.scope_info(scope);
        emit!(w, 0, "#[derive(Debug)]")?;
        emit!(w, 0, "pub enum {} {{", info.change_type())?;
        emit!(w, 1, "Create,")?;
        emit!(w, 1, "Delete,")?;
        if info.has_entry_changes {
            emit!(w, 1, "Entry({}),", info.entry_change_type())?;
        }
        emit!(w, 0, "}}")?;
        if !info.has_entry_changes {
            return Ok(());
        }
    }

    let name = ctx.scope_entry_change_type(scope);
    emit!(w, 0, "#[derive(Debug)]")?;
    emit!(w, 0, "pub enum {name} {{")?;
    for snode in ctx.change_nodes.iter().filter(|snode| {
        let parent = ctx.scope_parent(snode);
        parent.map(|parent| parent.path(SchemaPathFormat::DATA)) == scope_path
    }) {
        let variant = ctx.variant_name(snode);
        if snode.kind() == SchemaNodeKind::List {
            let info = ctx.scope_info(snode);
            emit!(
                w,
                1,
                "{variant}({}, {}),",
                info.keys_type(),
                info.change_type()
            )?;
        } else if let Some(ops) = variant_ops(snode) {
            emit!(w, 1, "{variant}({}),", ops.payload)?;
        }
    }
    emit!(w, 0, "}}")?;
    Ok(())
}

// Emits the statements that wrap a scope-local change value into the root
// ConfigChange enum, adding the keys of each enclosing list.
fn generate_wrap_stmts(
    w: &mut CodeWriter,
    ctx: &GenCtx<'_>,
    snode: &SchemaNode<'_>,
) -> std::fmt::Result {
    // Enclosing list chain, from innermost to outermost. For list nodes, the
    // chain includes the node itself.
    let mut lists = Vec::new();
    if snode.kind() == SchemaNodeKind::List {
        lists.push(snode.clone());
    }
    let mut cursor = snode.clone();
    while let Some(list) = ctx.scope_parent(&cursor) {
        lists.push(list.clone());
        cursor = list;
    }

    // Changes of an existing list entry are wrapped into the scope's change
    // enum. List creations and deletions are already scope-local values.
    if snode.kind() != SchemaNodeKind::List
        && let Some(scope) = ctx.scope_parent(snode)
    {
        emit!(
            w,
            2,
            "let change = {}::Entry(change);",
            ctx.scope_info(&scope).change_type()
        )?;
    }

    for list in lists {
        let scope = ctx.scope_parent(&list);
        let scope_type = ctx.scope_entry_change_type(scope.as_ref());
        let variant = ctx.variant_name(&list);
        let info = ctx.scope_info(&list);
        emit!(
            w,
            2,
            "let change = {scope_type}::{variant}({}(dnode)?, change);",
            info.keys_fn()
        )?;
        if let Some(scope) = scope {
            emit!(
                w,
                2,
                "let change = {}::Entry(change);",
                ctx.scope_info(&scope).change_type()
            )?;
        }
    }
    Ok(())
}

fn generate_parse_table(
    w: &mut CodeWriter,
    ctx: &GenCtx<'_>,
) -> std::fmt::Result {
    emit!(
        w,
        0,
        "const YANG_CONFIG_PARSE: phf::Map<&'static str, \
         ConfigChangeParseFn<ConfigChange>> = phf_map! {{"
    )?;
    for snode in &ctx.change_nodes {
        let path = snode.path(SchemaPathFormat::DATA);

        // Compute the match arms that build the scope-local change value.
        let (arms, uses_value) = if snode.kind() == SchemaNodeKind::List {
            let change_type = ctx.scope_info(snode).change_type();
            let arms = vec![
                ("ChangeOp::Create", format!("{change_type}::Create")),
                ("ChangeOp::Delete", format!("{change_type}::Delete")),
            ];
            (arms, false)
        } else {
            let Some(ops) = variant_ops(snode) else {
                continue;
            };
            let scope = ctx.scope_parent(snode);
            let scope_type = ctx.scope_entry_change_type(scope.as_ref());
            let variant = ctx.variant_name(snode);
            let arms = ops
                .arms
                .into_iter()
                .map(|(op_pat, expr)| {
                    (op_pat, format!("{scope_type}::{variant}({expr})"))
                })
                .collect::<Vec<_>>();
            let uses_value =
                arms.iter().any(|(_, expr)| expr.contains("value"));
            (arms, uses_value)
        };

        emit!(w, 1, "\"{path}\" => |op, dnode| {{")?;
        if uses_value {
            emit!(
                w,
                2,
                "let value = dnode.value_canonical()\
                 .ok_or(ParseError::MissingLeafValue)?;"
            )?;
        }
        emit!(w, 2, "let change = match op {{")?;
        for (op_pat, expr) in &arms {
            emit!(w, 3, "{op_pat} => {expr},")?;
        }
        emit!(w, 3, "_ => return Err(ParseError::UnexpectedOperation),")?;
        emit!(w, 2, "}};")?;
        generate_wrap_stmts(w, ctx, snode)?;
        emit!(w, 2, "Ok(change)")?;
        emit!(w, 1, "}},")?;
    }
    emit!(w, 0, "}};")?;
    Ok(())
}

fn generate_change_keys(
    w: &mut CodeWriter,
    ctx: &GenCtx<'_>,
) -> std::fmt::Result {
    emit!(w, 0, "static CHANGE_KEYS: &[(&str, ChangeOp)] = &[")?;
    for snode in &ctx.change_nodes {
        let path = snode.path(SchemaPathFormat::DATA);
        for op in [ChangeOp::Create, ChangeOp::Modify, ChangeOp::Delete] {
            if op.is_valid(snode) {
                emit!(w, 1, "(\"{path}\", ChangeOp::{op:?}),")?;
            }
        }
    }
    emit!(w, 0, "];")?;
    Ok(())
}

// ===== global functions =====

pub(crate) fn generate_yang_config(
    w: &mut CodeWriter,
    yang_ctx: &Context,
    modules: &[&str],
    path_root: Option<&str>,
) -> std::fmt::Result {
    let ctx = GenCtx::new(yang_ctx, modules, path_root);

    // Generate keys structs and their parsing functions.
    for snode in ctx.config_lists() {
        let info = ctx.scope_info(snode);
        generate_keys_struct(w, snode, info)?;
        generate_keys_fn(w, snode, info)?;
    }

    // Generate the change enum of each scope.
    generate_change_enum(w, &ctx, None)?;
    for snode in ctx.config_lists() {
        generate_change_enum(w, &ctx, Some(snode))?;
    }

    // Generate the parse dispatch table and change key registrations.
    generate_parse_table(w, &ctx)?;
    generate_change_keys(w, &ctx)?;

    emit!(
        w,
        0,
        "pub const YANG_OPS_CONFIG: YangConfigOps<ConfigChange> = \
         YangConfigOps {{"
    )?;
    emit!(w, 1, "parse: YANG_CONFIG_PARSE,")?;
    emit!(w, 1, "change_keys: CHANGE_KEYS,")?;
    emit!(w, 0, "}};")?;

    Ok(())
}
