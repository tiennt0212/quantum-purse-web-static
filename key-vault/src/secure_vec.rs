use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;
// use zeroize::ZeroizeOnDrop;

/// A secure vector that zeroizes its contents when dropped.
#[derive(Debug)]
pub struct SecureVec(Vec<u8>);

impl SecureVec {
    /// Creates a new SecureVec with the specified length, initialized with zeros.
    pub fn new_with_length(len: usize) -> Self {
        SecureVec(vec![0u8; len])
    }

    /// Creates a new SecureVec from a slice
    pub fn from_slice(slice: &[u8]) -> Self {
      SecureVec(slice.to_vec())
    }
}

// Implement Zeroize to wipe the contents of the inner Vec<u8>.
impl Zeroize for SecureVec {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// Ensure ZeroizeOnDrop is implemented (provided by the zeroize crate).
// impl ZeroizeOnDrop for SecureVec {}
impl Drop for SecureVec {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Implement Deref to allow SecureVec to be treated as &[u8].
impl Deref for SecureVec {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Implement DerefMut to allow SecureVec to be treated as &mut [u8].
impl DerefMut for SecureVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
