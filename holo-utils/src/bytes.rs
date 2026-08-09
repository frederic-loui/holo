//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

//! Panic-free byte buffers.
//!
//! [`Bytes`] and [`BytesMut`] are thin wrappers around the types of the same
//! name from the `bytes` crate. They expose only the subset of the original
//! API that can't panic. Every operation whose outcome depends on the amount
//! of data left in the buffer is named `try_*` and returns a [`Result`],
//! failing with [`TryGetError`] when the buffer is too short instead of
//! panicking.

use std::cell::RefCell;
use std::fmt::{self, Debug};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::{Deref, DerefMut, Range};

pub use bytes::TryGetError;
use bytes::{Buf, BufMut};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::mac_addr::MacAddr;

thread_local!(
    pub static TLS_BUF: RefCell<BytesMut> =
        RefCell::new(BytesMut::with_capacity(65536))
);

/// A cheaply cloneable and sliceable chunk of contiguous memory.
#[derive(Clone, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
#[serde(transparent)]
pub struct Bytes(bytes::Bytes);

/// A unique reference to a contiguous slice of memory.
#[derive(Clone, Default, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
#[serde(transparent)]
pub struct BytesMut(bytes::BytesMut);

// ===== impl Bytes =====

impl Bytes {
    /// Creates a new empty `Bytes`.
    ///
    /// This will not allocate and the returned `Bytes` handle will be empty.
    pub const fn new() -> Self {
        Bytes(bytes::Bytes::new())
    }

    /// Creates `Bytes` instance from slice, by copying it.
    pub fn copy_from_slice(data: &[u8]) -> Self {
        Bytes(bytes::Bytes::copy_from_slice(data))
    }

    /// Returns the number of bytes contained in this `Bytes`.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the `Bytes` has a length of 0.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of bytes between the current position and the end
    /// of the buffer.
    pub fn remaining(&self) -> usize {
        self.0.remaining()
    }

    /// Returns a slice of self for the provided range.
    ///
    /// This will increment the reference count for the underlying memory and
    /// return a new `Bytes` handle set to the slice. This operation is `O(1)`.
    ///
    /// Returns `Err(TryGetError)` when the range extends past the end of the
    /// buffer.
    pub fn try_slice(&self, range: Range<usize>) -> Result<Bytes, TryGetError> {
        let available = self.0.len();
        if range.start > range.end || range.end > available {
            return Err(TryGetError {
                requested: range.end,
                available,
            });
        }
        Ok(Bytes(self.0.slice(range)))
    }

    /// Shortens the buffer, keeping the first `len` bytes and dropping the
    /// rest.
    ///
    /// If `len` is greater than the buffer's current length, this has no
    /// effect.
    pub fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }

    /// Clears the buffer, removing all data.
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// Advances the internal cursor of the buffer.
    ///
    /// Returns `Err(TryGetError)` when there are not enough remaining bytes.
    pub fn try_advance(&mut self, cnt: usize) -> Result<(), TryGetError> {
        self.check_remaining(cnt)?;
        self.0.advance(cnt);
        Ok(())
    }

    /// Consumes `len` bytes inside self and returns new instance of `Bytes`
    /// with this data.
    ///
    /// This is a shallow copy (ref-count increment), no data is moved.
    ///
    /// Returns `Err(TryGetError)` when there are not enough remaining bytes.
    pub fn try_copy_to_bytes(
        &mut self,
        len: usize,
    ) -> Result<Bytes, TryGetError> {
        self.check_remaining(len)?;
        Ok(Bytes(self.0.copy_to_bytes(len)))
    }

    /// Copies bytes from `self` into `dst`.
    ///
    /// The cursor is advanced by the number of bytes copied.
    ///
    /// Returns `Err(TryGetError)` when there are not enough remaining bytes to
    /// read the value.
    pub fn try_copy_to_slice(
        &mut self,
        dst: &mut [u8],
    ) -> Result<(), TryGetError> {
        self.0.try_copy_to_slice(dst)
    }

    /// Gets an unsigned 8 bit integer from `self`.
    ///
    /// The current position is advanced by 1.
    ///
    /// Returns `Err(TryGetError)` when there are not enough remaining bytes to
    /// read the value.
    pub fn try_get_u8(&mut self) -> Result<u8, TryGetError> {
        self.0.try_get_u8()
    }

    /// Gets an unsigned 16 bit integer from `self` in big-endian byte order.
    ///
    /// The current position is advanced by 2.
    ///
    /// Returns `Err(TryGetError)` when there are not enough remaining bytes to
    /// read the value.
    pub fn try_get_u16(&mut self) -> Result<u16, TryGetError> {
        self.0.try_get_u16()
    }

    /// Gets an unsigned 24 bit integer from `self` in big-endian byte order.
    ///
    /// The current position is advanced by 3.
    ///
    /// Returns `Err(TryGetError)` when there are not enough remaining bytes to
    /// read the value.
    pub fn try_get_u24(&mut self) -> Result<u32, TryGetError> {
        let mut n = [0; 4];
        self.try_copy_to_slice(&mut n[1..=3])?;
        Ok(u32::from_be_bytes(n))
    }

    /// Gets an unsigned 32 bit integer from `self` in big-endian byte order.
    ///
    /// The current position is advanced by 4.
    ///
    /// Returns `Err(TryGetError)` when there are not enough remaining bytes to
    /// read the value.
    pub fn try_get_u32(&mut self) -> Result<u32, TryGetError> {
        self.0.try_get_u32()
    }

    /// Gets a signed 32 bit integer from `self` in big-endian byte order.
    ///
    /// The current position is advanced by 4.
    ///
    /// Returns `Err(TryGetError)` when there are not enough remaining bytes to
    /// read the value.
    pub fn try_get_i32(&mut self) -> Result<i32, TryGetError> {
        self.0.try_get_i32()
    }

    /// Gets an unsigned 64 bit integer from `self` in big-endian byte order.
    ///
    /// The current position is advanced by 8.
    ///
    /// Returns `Err(TryGetError)` when there are not enough remaining bytes to
    /// read the value.
    pub fn try_get_u64(&mut self) -> Result<u64, TryGetError> {
        self.0.try_get_u64()
    }

    /// Gets an unsigned 128 bit integer from `self` in big-endian byte order.
    ///
    /// The current position is advanced by 16.
    ///
    /// Returns `Err(TryGetError)` when there are not enough remaining bytes to
    /// read the value.
    pub fn try_get_u128(&mut self) -> Result<u128, TryGetError> {
        self.0.try_get_u128()
    }

    /// Gets an IEEE754 single-precision (4 bytes) floating point number from
    /// `self` in big-endian byte order.
    ///
    /// The current position is advanced by 4.
    ///
    /// Returns `Err(TryGetError)` when there are not enough remaining bytes to
    /// read the value.
    pub fn try_get_f32(&mut self) -> Result<f32, TryGetError> {
        self.0.try_get_f32()
    }

    /// Gets an IPv4 address from `self` in big-endian byte order.
    ///
    /// The current position is advanced by 4.
    ///
    /// Returns `Err(TryGetError)` when there are not enough remaining bytes to
    /// read the value.
    pub fn try_get_ipv4(&mut self) -> Result<Ipv4Addr, TryGetError> {
        let bytes = self.try_get_u32()?;
        Ok(Ipv4Addr::from(bytes))
    }

    /// Gets an optional IPv4 address from `self` in big-endian byte order.
    ///
    /// The current position is advanced by 4.
    ///
    /// Returns `Err(TryGetError)` when there are not enough remaining bytes to
    /// read the value.
    pub fn try_get_opt_ipv4(
        &mut self,
    ) -> Result<Option<Ipv4Addr>, TryGetError> {
        let addr = self.try_get_ipv4()?;
        Ok((!addr.is_unspecified()).then_some(addr))
    }

    /// Gets an IPv6 address from `self` in big-endian byte order.
    ///
    /// The current position is advanced by 16.
    ///
    /// Returns `Err(TryGetError)` when there are not enough remaining bytes to
    /// read the value.
    pub fn try_get_ipv6(&mut self) -> Result<Ipv6Addr, TryGetError> {
        let bytes = self.try_get_u128()?;
        Ok(Ipv6Addr::from(bytes))
    }

    /// Gets an optional IPv6 address from `self` in big-endian byte order.
    ///
    /// The current position is advanced by 16.
    ///
    /// Returns `Err(TryGetError)` when there are not enough remaining bytes to
    /// read the value.
    pub fn try_get_opt_ipv6(
        &mut self,
    ) -> Result<Option<Ipv6Addr>, TryGetError> {
        let addr = self.try_get_ipv6()?;
        Ok((!addr.is_unspecified()).then_some(addr))
    }

    /// Gets a MAC address from `self`.
    ///
    /// The current position is advanced by 6.
    ///
    /// Returns `Err(TryGetError)` when there are not enough remaining bytes to
    /// read the value.
    pub fn try_get_mac(&mut self) -> Result<MacAddr, TryGetError> {
        let mut bytes: [u8; MacAddr::LENGTH] = [0; MacAddr::LENGTH];
        self.try_copy_to_slice(&mut bytes)?;
        Ok(MacAddr::from(bytes))
    }

    /// Returns `Err(TryGetError)` when fewer than `cnt` bytes are left.
    fn check_remaining(&self, cnt: usize) -> Result<(), TryGetError> {
        let available = self.0.len();
        if cnt > available {
            return Err(TryGetError {
                requested: cnt,
                available,
            });
        }
        Ok(())
    }
}

impl Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(vec: Vec<u8>) -> Self {
        Bytes(bytes::Bytes::from(vec))
    }
}

impl PartialEq<&[u8]> for Bytes {
    fn eq(&self, other: &&[u8]) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Bytes> for &[u8] {
    fn eq(&self, other: &Bytes) -> bool {
        other.0 == *self
    }
}

impl<'a> arbitrary::Arbitrary<'a> for Bytes {
    fn arbitrary(
        u: &mut arbitrary::Unstructured<'a>,
    ) -> arbitrary::Result<Self> {
        let len = u.len();
        let bytes = u.bytes(len)?;
        Ok(Bytes::copy_from_slice(bytes))
    }
}

// ===== impl BytesMut =====

impl BytesMut {
    /// Creates a new empty `BytesMut`.
    pub fn new() -> Self {
        BytesMut(bytes::BytesMut::new())
    }

    /// Creates a new `BytesMut` with the specified capacity.
    ///
    /// The returned `BytesMut` will be able to hold at least `capacity` bytes
    /// without reallocating.
    ///
    /// It is important to note that this function does not specify the length
    /// of the returned `BytesMut`, but only the capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        BytesMut(bytes::BytesMut::with_capacity(capacity))
    }

    /// Creates a new `BytesMut` containing `len` zeros.
    ///
    /// The resulting object has a length of `len` and a capacity greater than
    /// or equal to `len`. The entire length of the object will be filled with
    /// zeros.
    ///
    /// On some platforms or allocators this function may be faster than a
    /// manual implementation.
    pub fn zeroed(len: usize) -> Self {
        BytesMut(bytes::BytesMut::zeroed(len))
    }

    /// Returns the number of bytes contained in this `BytesMut`.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the `BytesMut` has a length of 0.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Converts `self` into an immutable `Bytes`.
    ///
    /// The conversion is zero cost and is used to indicate that the slice
    /// referenced by the handle will no longer be mutated. Once the conversion
    /// is done, the handle can be cloned and shared across threads.
    pub fn freeze(self) -> Bytes {
        Bytes(self.0.freeze())
    }

    /// Splits the bytes into two at the given index.
    ///
    /// Afterwards `self` contains elements `[0, at)`, and the returned
    /// `BytesMut` contains elements `[at, capacity)`. It's guaranteed that the
    /// memory does not move, that is, the address of `self` does not change,
    /// and the address of the returned slice is `at` bytes after that.
    ///
    /// This is an `O(1)` operation that just increases the reference count and
    /// sets a few indices.
    ///
    /// Returns `Err(TryGetError)` when `at` is beyond the end of the buffer.
    pub fn try_split_off(
        &mut self,
        at: usize,
    ) -> Result<BytesMut, TryGetError> {
        self.check_remaining(at)?;
        Ok(BytesMut(self.0.split_off(at)))
    }

    /// Shortens the buffer, keeping the first `len` bytes and dropping the
    /// rest.
    ///
    /// If `len` is greater than the buffer's current length, this has no
    /// effect. Existing underlying capacity is preserved.
    pub fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }

    /// Clears the buffer, removing all data. Existing capacity is preserved.
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// Resizes the buffer so that `len` is equal to `new_len`.
    ///
    /// If `new_len` is greater than `len`, the buffer is extended by the
    /// difference with each additional byte set to `value`. If `new_len` is
    /// less than `len`, the buffer is simply truncated.
    pub fn resize(&mut self, new_len: usize, value: u8) {
        self.0.resize(new_len, value);
    }

    /// Advances the internal cursor of the buffer.
    ///
    /// Returns `Err(TryGetError)` when there are not enough remaining bytes.
    pub fn try_advance(&mut self, cnt: usize) -> Result<(), TryGetError> {
        self.check_remaining(cnt)?;
        self.0.advance(cnt);
        Ok(())
    }

    /// Reads data from `src` and appends it to the buffer, growing it as
    /// needed.
    ///
    /// Returns the number of bytes read, zero meaning end of file.
    pub async fn read_from<R>(&mut self, src: &mut R) -> io::Result<usize>
    where
        R: AsyncRead + Unpin,
    {
        src.read_buf(&mut self.0).await
    }

    /// Transfer bytes into `self` from `src` and advance the cursor by the
    /// number of bytes written.
    pub fn put_slice(&mut self, src: &[u8]) {
        self.0.put_slice(src);
    }

    /// Put `cnt` bytes `val` into `self`.
    ///
    /// Logically equivalent to calling `self.put_u8(val)` `cnt` times, but may
    /// work faster.
    pub fn put_bytes(&mut self, val: u8, cnt: usize) {
        self.0.put_bytes(val, cnt);
    }

    /// Writes an unsigned 8 bit integer to `self`.
    ///
    /// The current position is advanced by 1.
    pub fn put_u8(&mut self, n: u8) {
        self.0.put_u8(n);
    }

    /// Writes an unsigned 16 bit integer to `self` in big-endian byte order.
    ///
    /// The current position is advanced by 2.
    pub fn put_u16(&mut self, n: u16) {
        self.0.put_u16(n);
    }

    /// Writes an unsigned 24 bit integer to `self` in big-endian byte order.
    ///
    /// The current position is advanced by 3.
    pub fn put_u24(&mut self, n: u32) {
        let n = n.to_be_bytes();
        self.put_slice(&n[1..=3]);
    }

    /// Writes an unsigned 32 bit integer to `self` in big-endian byte order.
    ///
    /// The current position is advanced by 4.
    pub fn put_u32(&mut self, n: u32) {
        self.0.put_u32(n);
    }

    /// Writes a signed 32 bit integer to `self` in big-endian byte order.
    ///
    /// The current position is advanced by 4.
    pub fn put_i32(&mut self, n: i32) {
        self.0.put_i32(n);
    }

    /// Writes an unsigned 64 bit integer to `self` in big-endian byte order.
    ///
    /// The current position is advanced by 8.
    pub fn put_u64(&mut self, n: u64) {
        self.0.put_u64(n);
    }

    /// Writes an unsigned 128 bit integer to `self` in big-endian byte order.
    ///
    /// The current position is advanced by 16.
    pub fn put_u128(&mut self, n: u128) {
        self.0.put_u128(n);
    }

    /// Writes an IEEE754 single-precision (4 bytes) floating point number to
    /// `self` in big-endian byte order.
    ///
    /// The current position is advanced by 4.
    pub fn put_f32(&mut self, n: f32) {
        self.0.put_f32(n);
    }

    /// Writes an IP address to `self` in big-endian byte order.
    ///
    /// The current position is advanced by 4 or 16.
    pub fn put_ip(&mut self, addr: &IpAddr) {
        match addr {
            IpAddr::V4(addr) => self.put_slice(&addr.octets()),
            IpAddr::V6(addr) => self.put_slice(&addr.octets()),
        }
    }

    /// Writes an IPv4 address to `self` in big-endian byte order.
    ///
    /// The current position is advanced by 4.
    pub fn put_ipv4(&mut self, addr: &Ipv4Addr) {
        self.put_slice(&addr.octets());
    }

    /// Writes an IPv6 address to `self` in big-endian byte order.
    ///
    /// The current position is advanced by 16.
    pub fn put_ipv6(&mut self, addr: &Ipv6Addr) {
        self.put_slice(&addr.octets());
    }

    /// Writes a MAC address to `self`.
    ///
    /// The current position is advanced by 6.
    pub fn put_mac(&mut self, addr: &MacAddr) {
        self.put_slice(&addr.as_bytes());
    }

    /// Returns `Err(TryGetError)` when fewer than `cnt` bytes are left.
    fn check_remaining(&self, cnt: usize) -> Result<(), TryGetError> {
        let available = self.0.len();
        if cnt > available {
            return Err(TryGetError {
                requested: cnt,
                available,
            });
        }
        Ok(())
    }
}

impl Debug for BytesMut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl Deref for BytesMut {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl DerefMut for BytesMut {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for BytesMut {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for BytesMut {
    fn from(slice: &[u8]) -> Self {
        BytesMut(bytes::BytesMut::from(slice))
    }
}

impl PartialEq<&[u8]> for BytesMut {
    fn eq(&self, other: &&[u8]) -> bool {
        self.0 == *other
    }
}

impl PartialEq<BytesMut> for &[u8] {
    fn eq(&self, other: &BytesMut) -> bool {
        other.0 == *self
    }
}
