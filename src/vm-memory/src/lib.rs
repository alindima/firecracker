// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! This is a "proxy" crate for Firecracker. It links to upstream vm-memory implementation
//! and re-exports symbols for consumption.
//! This crate implements a custom vm-memory backend implementation that overrides the
//! upstream implementation and adds dirty page tracking functionality.

// Export local backend implementation.

// Re-export only what is needed in Firecracker.
pub use vm_memory_upstream::{
    address, bitmap::Bitmap, mmap::MmapRegionError, Address, ByteValued, Bytes, Error, FileOffset,
    GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryRegion, GuestUsize,
    MemoryRegionAddress, MmapRegion,
};

use std::default::Default;
use std::sync::atomic::{AtomicBool, Ordering};

use vm_memory_upstream::bitmap::{AtomicBitmap, RefSlice, WithBitmapSlice};
use vm_memory_upstream::mmap::NewBitmap;
use vm_memory_upstream::{
    GuestMemoryMmap as UpstreamGuestMemoryMmap, GuestRegionMmap as UpstreamGuestRegionMmap,
};

pub type GuestMemoryMmap = UpstreamGuestMemoryMmap<MyBitmap>;
pub type GuestRegionMmap = UpstreamGuestRegionMmap<MyBitmap>;

#[derive(Debug)]
pub struct MyBitmap {
    enabled: AtomicBool,
    inner: AtomicBitmap,
}

impl Clone for MyBitmap {
    fn clone(&self) -> Self {
        Self {
            enabled: AtomicBool::new(self.enabled()),
            inner: self.inner.clone(),
        }
    }
}

impl MyBitmap {
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    pub fn enable(&self) {
        if !self.enabled() {
            self.enabled.store(true, Ordering::Release)
        }
    }

    pub fn reset(&self) {
        if self.enabled() {
            self.inner.reset()
        }
    }
}

impl Default for MyBitmap {
    fn default() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            inner: AtomicBitmap::default(),
        }
    }
}

impl<'a> WithBitmapSlice<'a> for MyBitmap {
    type S = RefSlice<'a, AtomicBitmap>;
}

impl NewBitmap for MyBitmap {
    fn with_len(len: usize) -> Self {
        Self {
            enabled: AtomicBool::new(false),
            inner: AtomicBitmap::with_len(len),
        }
    }
}

impl Bitmap for MyBitmap {
    fn mark_dirty(&self, offset: usize, len: usize) {
        if self.enabled() {
            self.inner.mark_dirty(offset, len)
        }
    }

    fn dirty_at(&self, offset: usize) -> bool {
        if self.enabled() {
            self.inner.dirty_at(offset)
        } else {
            false
        }
    }

    fn slice_at(&self, offset: usize) -> <Self as WithBitmapSlice>::S {
        self.inner.slice_at(offset)
    }
}

fn enable_dirty_bitmap_tracking(mem: &GuestMemoryMmap) {
    for region in mem.iter() {
        region.bitmap().enable();
    }
}

// todo setup guard pages!

/// Creates GuestMemory of `mem_size_mib` MiB in size.
pub fn create_guest_memory_with_ranges(
    ranges: &[(GuestAddress, usize)],
    track_dirty_pages: bool,
) -> std::result::Result<GuestMemoryMmap, Error> {
    let guest_mem = GuestMemoryMmap::from_ranges(ranges)?;
    if track_dirty_pages {
        enable_dirty_bitmap_tracking(&guest_mem);
    }
    Ok(guest_mem)
}

pub fn create_guest_memory_with_regions(
    regions: Vec<GuestRegionMmap>,
    track_dirty_pages: bool,
) -> std::result::Result<GuestMemoryMmap, Error> {
    let guest_mem = GuestMemoryMmap::from_regions(regions)?;
    if track_dirty_pages {
        enable_dirty_bitmap_tracking(&guest_mem);
    }
    Ok(guest_mem)
}
