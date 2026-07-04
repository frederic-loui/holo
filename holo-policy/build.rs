//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::yang_codegen;
use holo_northbound::yang_codegen::types::TypeSpec;
use holo_yang as yang;

// Routing-policy-specific YANG types.
static TYPEDEFS: &[(&str, TypeSpec)] = &[
    (
        "bgp-ext-community-type",
        TypeSpec {
            rust_type: "ExtComm",
            copy_semantics: true,
        },
    ),
    (
        "bgp-ipv6-ext-community-type",
        TypeSpec {
            rust_type: "Extv6Comm",
            copy_semantics: true,
        },
    ),
    (
        "bgp-large-community-type",
        TypeSpec {
            rust_type: "LargeComm",
            copy_semantics: true,
        },
    ),
    (
        "bgp-next-hop-type",
        TypeSpec {
            rust_type: "BgpNexthop",
            copy_semantics: true,
        },
    ),
    (
        "bgp-origin-attr-type",
        TypeSpec {
            rust_type: "Origin",
            copy_semantics: true,
        },
    ),
    (
        "bgp-set-community-option-type",
        TypeSpec {
            rust_type: "BgpSetCommOptions",
            copy_semantics: true,
        },
    ),
    (
        "bgp-set-med-type",
        TypeSpec {
            rust_type: "BgpSetMed",
            copy_semantics: true,
        },
    ),
    (
        "metric-modification-type",
        TypeSpec {
            rust_type: "MetricModification",
            copy_semantics: true,
        },
    ),
    (
        "tag-type",
        TypeSpec {
            rust_type: "RouteTag",
            copy_semantics: true,
        },
    ),
];

// Routing-policy-specific YANG identity types.
static IDENTITY_TYPES: &[(&str, TypeSpec)] = &[
    (
        "afi-safi-type",
        TypeSpec {
            rust_type: "AfiSafi",
            copy_semantics: true,
        },
    ),
    (
        "control-plane-protocol",
        TypeSpec {
            rust_type: "Protocol",
            copy_semantics: true,
        },
    ),
    (
        "metric-type",
        TypeSpec {
            rust_type: "MetricType",
            copy_semantics: true,
        },
    ),
    (
        "proto-route-type",
        TypeSpec {
            rust_type: "RouteType",
            copy_semantics: true,
        },
    ),
    (
        "route-level",
        TypeSpec {
            rust_type: "RouteLevel",
            copy_semantics: true,
        },
    ),
];

// Routing-policy-specific YANG leaf types.
static LEAF_TYPES: &[(&str, TypeSpec)] = &[
    (
        "/ietf-routing-policy:routing-policy/defined-sets/prefix-sets/prefix-set/mode",
        TypeSpec {
            rust_type: "AddressFamily",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing-policy:routing-policy/policy-definitions/policy-definition/statements/statement/conditions/match-prefix-set/match-set-options",
        TypeSpec {
            rust_type: "MatchSetRestrictedType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing-policy:routing-policy/policy-definitions/policy-definition/statements/statement/conditions/match-tag-set/match-set-options",
        TypeSpec {
            rust_type: "MatchSetType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing-policy:routing-policy/policy-definitions/policy-definition/statements/statement/conditions/ietf-bgp-policy:bgp-conditions/route-type",
        TypeSpec {
            rust_type: "holo_utils::bgp::RouteType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing-policy:routing-policy/policy-definitions/policy-definition/statements/statement/conditions/ietf-bgp-policy:bgp-conditions/match-afi-safi/match-set-options",
        TypeSpec {
            rust_type: "MatchSetRestrictedType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing-policy:routing-policy/policy-definitions/policy-definition/statements/statement/conditions/ietf-bgp-policy:bgp-conditions/match-neighbor/match-set-options",
        TypeSpec {
            rust_type: "MatchSetRestrictedType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing-policy:routing-policy/policy-definitions/policy-definition/statements/statement/conditions/ietf-bgp-policy:bgp-conditions/match-community-set/match-set-options",
        TypeSpec {
            rust_type: "MatchSetType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing-policy:routing-policy/policy-definitions/policy-definition/statements/statement/conditions/ietf-bgp-policy:bgp-conditions/match-ext-community-set/match-set-options",
        TypeSpec {
            rust_type: "MatchSetType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing-policy:routing-policy/policy-definitions/policy-definition/statements/statement/conditions/ietf-bgp-policy:bgp-conditions/match-ipv6-ext-community-set/match-set-options",
        TypeSpec {
            rust_type: "MatchSetType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing-policy:routing-policy/policy-definitions/policy-definition/statements/statement/conditions/ietf-bgp-policy:bgp-conditions/match-large-community-set/match-set-options",
        TypeSpec {
            rust_type: "MatchSetType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing-policy:routing-policy/policy-definitions/policy-definition/statements/statement/conditions/ietf-bgp-policy:bgp-conditions/match-as-path-set/match-set-options",
        TypeSpec {
            rust_type: "MatchSetType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing-policy:routing-policy/policy-definitions/policy-definition/statements/statement/conditions/ietf-bgp-policy:bgp-conditions/match-next-hop-set/match-set-options",
        TypeSpec {
            rust_type: "MatchSetRestrictedType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing-policy:routing-policy/policy-definitions/policy-definition/statements/statement/actions/ietf-bgp-policy:bgp-actions/set-community/communities",
        TypeSpec {
            rust_type: "Comm",
            copy_semantics: true,
        },
    ),
];

fn main() {
    let mut yang_ctx = yang::new_context();
    let modules = yang::implemented_modules::POLICY;
    yang::load_modules(&mut yang_ctx, modules);
    yang_codegen::types::register_typedefs(TYPEDEFS);
    yang_codegen::types::register_identity_types(&yang_ctx, IDENTITY_TYPES);
    yang_codegen::types::register_leaf_types(&yang_ctx, LEAF_TYPES);
    yang_codegen::build_yang_objects(&yang_ctx, modules, "yang_objects.rs");
    yang_codegen::build_yang_ops(&yang_ctx, modules, None, "yang_ops.rs");
    yang_codegen::build_yang_config(&yang_ctx, modules, None, "yang_config.rs");
}
