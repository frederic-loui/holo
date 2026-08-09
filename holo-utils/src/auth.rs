//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha_crypt::{PasswordVerifier, ShaCrypt};

// Local user accounts, keyed by user name.
pub type Users = Arc<BTreeMap<String, User>>;

// Local user account.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct User {
    // Password hash, in one of the crypt(3) formats of RFC 7317.
    pub password: Option<String>,
}

// ===== impl User =====

impl User {
    // Checks a password against the user's hash, in constant time.
    pub fn verify_password(&self, password: &str) -> bool {
        let Some(hash) = &self.password else {
            return false;
        };

        ShaCrypt::default()
            .verify_password(password.as_bytes(), hash.as_str())
            .is_ok()
    }
}
