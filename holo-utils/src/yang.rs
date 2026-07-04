//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::ffi::CString;

use holo_yang::TryFromYang;
use tracing::error;
use yang5::context::Context;
use yang5::data::{Data, DataNodeRef, DataTree};
use yang5::schema::{
    DataValueType, SchemaLeafType, SchemaNode, SchemaPathFormat,
};

//
// YANG path type.
//
// Instances of this structure are created automatically at build-time, and
// their use should be preferred over regular strings for extra type safety.
//
#[derive(Clone, Copy, Debug)]
pub struct YangPath(&'static str);

/// Extension methods for `Context`.
pub trait ContextExt {
    /// Caches the data path of every schema node in the context.
    fn cache_data_paths(&self);
}

/// Extension methods for `SchemaNode`.
pub trait SchemaNodeExt {
    /// Computes the data path of the schema node and stores it in the node's
    /// private pointer.
    fn cache_data_path(&self);

    /// Returns the cached data path of the schema node.
    ///
    /// # Panics
    ///
    /// Panics if the data path hasn't been cached yet.
    fn data_path(&self) -> String;
}

/// Extension methods for `SchemaLeafType`.
pub trait SchemaLeafTypeExt {
    /// Returns the names of the identities listed in the `base` statements
    /// of an identityref leaf type. Returns an empty vector for leaf types
    /// of any other kind.
    fn identityref_bases(&self) -> Vec<String>;
}

/// Extension methods for `DataTree`.
pub trait DataTreeExt {
    /// Iterates over all data nodes matching the given schema path. Logs an
    /// error and yields no nodes if the path fails to evaluate.
    fn iter_path(
        &self,
        path: YangPath,
    ) -> Box<dyn Iterator<Item = DataNodeRef<'_>> + '_>;
}

/// Extension methods for `DataNodeRef`.
pub trait DataNodeRefExt {
    /// Returns whether the given relative XPath expression matches at least
    /// one data node.
    fn exists(&self, path: &str) -> bool;

    /// Returns the canonical string value of the data node.
    fn get_string(&self) -> String;

    /// Returns the canonical string value of the data node found by the given
    /// relative XPath expression.
    fn get_string_relative(&self, path: &str) -> Option<String>;

    /// Returns the typed value of the data node.
    fn get_typed<T: TryFromYang>(&self) -> Option<T>;

    /// Returns the typed value of the data node found by the given relative
    /// XPath expression.
    fn get_typed_relative<T: TryFromYang>(&self, path: &str) -> Option<T>;

    /// Returns the typed value of the first descendant matching the given
    /// schema path.
    fn get_typed_path<T: TryFromYang>(&self, path: YangPath) -> Option<T>;

    /// Returns the nearest inclusive ancestor matching the given schema path.
    fn ancestor(&self, path: YangPath) -> Option<DataNodeRef<'_>>;

    /// Iterates over all descendants matching the given schema path. Logs an
    /// error and yields no nodes if the path isn't relative to this node or
    /// fails to evaluate.
    fn iter_path(
        &self,
        path: YangPath,
    ) -> Box<dyn Iterator<Item = DataNodeRef<'_>> + '_>;
}

// ===== impl YangPath =====

impl YangPath {
    pub const fn new(path: &'static str) -> YangPath {
        YangPath(path)
    }
}

impl std::fmt::Display for YangPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for YangPath {
    fn as_ref(&self) -> &str {
        self.0
    }
}

// ===== impl Context =====

impl ContextExt for Context {
    fn cache_data_paths(&self) {
        for snode in self.traverse() {
            snode.cache_data_path();
            for action in snode.actions() {
                for snode in action.traverse() {
                    snode.cache_data_path();
                }
            }
            for notification in snode.notifications() {
                for snode in notification.traverse() {
                    snode.cache_data_path();
                }
            }
        }
    }
}

// ===== impl SchemaNode =====

impl SchemaNodeExt for SchemaNode<'_> {
    fn cache_data_path(&self) {
        let data_path = self.path(SchemaPathFormat::DATA);
        let data_path = CString::new(data_path).unwrap();
        unsafe { self.set_private(data_path.into_raw() as _) };
    }

    fn data_path(&self) -> String {
        let data_path = self
            .get_private()
            .expect("Schema node private pointer uninitialized");
        let data_path = unsafe { std::ffi::CStr::from_ptr(data_path as _) };
        data_path.to_str().expect("Invalid UTF-8").to_owned()
    }
}

// ===== impl SchemaLeafType =====

impl SchemaLeafTypeExt for SchemaLeafType<'_> {
    fn identityref_bases(&self) -> Vec<String> {
        let mut bases = Vec::new();
        if self.base_type() != DataValueType::IdentityRef {
            return bases;
        }
        // SAFETY: the compiled type of an identityref is a
        // `lysc_type_identityref`, whose bases field is a libyang sized
        // array storing its length in the 64 bits that precede the first
        // element.
        unsafe {
            let raw = self.as_raw() as *const yang5::ffi::lysc_type_identityref;
            let array = (*raw).bases;
            if array.is_null() {
                return bases;
            }
            let count = *(array as *const u64).sub(1);
            for idx in 0..count as usize {
                let ident = *array.add(idx);
                let name = std::ffi::CStr::from_ptr((*ident).name);
                bases.push(name.to_string_lossy().into_owned());
            }
        }
        bases
    }
}

// ===== impl DataTree =====

impl DataTreeExt for DataTree<'_> {
    fn iter_path(
        &self,
        path: YangPath,
    ) -> Box<dyn Iterator<Item = DataNodeRef<'_>> + '_> {
        match self.find_xpath(path.as_ref()) {
            Ok(dnodes) => Box::new(dnodes),
            Err(error) => {
                error!(%path, %error, "failed to evaluate XPath expression");
                Box::new(std::iter::empty())
            }
        }
    }
}

// ===== impl DataNodeRef =====

impl DataNodeRefExt for DataNodeRef<'_> {
    fn exists(&self, path: &str) -> bool {
        self.find_xpath(path).unwrap().next().is_some()
    }

    fn get_string(&self) -> String {
        self.value_canonical()
            .expect("data node doesn't hold any value")
    }

    fn get_string_relative(&self, path: &str) -> Option<String> {
        self.find_xpath(path)
            .unwrap()
            .next()
            .map(|dnode| dnode.get_string())
    }

    fn get_typed<T: TryFromYang>(&self) -> Option<T> {
        let value = self.value_canonical()?;
        T::try_from_yang(&value)
    }

    fn get_typed_relative<T: TryFromYang>(&self, path: &str) -> Option<T> {
        let value = self.get_string_relative(path)?;
        T::try_from_yang(&value)
    }

    fn get_typed_path<T: TryFromYang>(&self, path: YangPath) -> Option<T> {
        self.iter_path(path)
            .next()
            .and_then(|dnode| dnode.get_typed())
    }

    fn ancestor(&self, path: YangPath) -> Option<DataNodeRef<'_>> {
        self.inclusive_ancestors()
            .find(|dnode| dnode.schema().data_path() == path.as_ref())
    }

    fn iter_path(
        &self,
        path: YangPath,
    ) -> Box<dyn Iterator<Item = DataNodeRef<'_>> + '_> {
        let data_path = self.schema().data_path();
        let Some(suffix) = path.as_ref().strip_prefix(&data_path) else {
            error!(%path, node = %data_path, "schema path isn't relative to the data node");
            return Box::new(std::iter::empty());
        };
        match self.find_xpath(&format!(".{suffix}")) {
            Ok(dnodes) => Box::new(dnodes),
            Err(error) => {
                error!(%path, %error, "failed to evaluate XPath expression");
                Box::new(std::iter::empty())
            }
        }
    }
}
