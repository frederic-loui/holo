//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::yang_codegen;
use holo_northbound::yang_codegen::types::TypeSpec;
use holo_yang as yang;

// Keychain-specific YANG identity types.
static IDENTITY_TYPES: &[(&str, TypeSpec)] = &[(
    "crypto-algorithm",
    TypeSpec {
        rust_type: "CryptoAlgo",
        copy_semantics: true,
    },
)];

fn main() {
    let mut yang_ctx = yang::new_context();
    let modules = yang::implemented_modules::KEYCHAIN;
    yang::load_modules(&mut yang_ctx, modules);
    yang_codegen::types::register_identity_types(&yang_ctx, IDENTITY_TYPES);
    yang_codegen::build_yang_objects(&yang_ctx, modules, "yang_objects.rs");
    yang_codegen::build_yang_ops(&yang_ctx, modules, None, "yang_ops.rs");
    yang_codegen::build_yang_config(&yang_ctx, modules, None, "yang_config.rs");
}
