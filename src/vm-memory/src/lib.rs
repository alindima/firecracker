// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! // TODO: fix all the unwraps in create_guest_memory
//! // TODO: add unit tests for this code
//! // TODO: Replace the MyBitmap type with an Option<AtomicBitmap>, once the builder pattern
//!    for the mmapregion becomes available.

// Export local backend implementation.

// Re-export only what is needed in Firecracker.
pub use vm_memory_upstream::{
    address, bitmap::Bitmap, mmap::MmapRegionError, Address, ByteValued, Bytes, Error, FileOffset,
    GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryRegion, GuestUsize,
    MemoryRegionAddress,
};

use std::default::Default;
use std::io::Error as IoError;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};

use vm_memory_upstream::bitmap::{AtomicBitmap, RefSlice, WithBitmapSlice};
use vm_memory_upstream::mmap::{check_file_offset, NewBitmap};
use vm_memory_upstream::{
    GuestMemoryMmap as UpstreamGuestMemoryMmap, GuestRegionMmap as UpstreamGuestRegionMmap,
    MmapRegion as UpstreamMmapRegion,
};

pub type GuestMemoryMmap = UpstreamGuestMemoryMmap<MyBitmap>;
pub type GuestRegionMmap = UpstreamGuestRegionMmap<MyBitmap>;
pub type MmapRegion = UpstreamMmapRegion<MyBitmap>;

const GUARD_NUMBER: usize = 2;

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

fn enable_dirty_page_tracking(mem: &GuestMemoryMmap) {
    for region in mem.iter() {
        region.bitmap().enable();
    }
}

fn build_guarded_region(
    file_offset: Option<FileOffset>,
    size: usize,
    prot: i32,
    flags: i32,
) -> Result<MmapRegion, MmapRegionError> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    // Create the guarded range size (received size + X pages),
    // where X is defined as a constant GUARD_NUMBER.
    let guarded_size = size + GUARD_NUMBER * page_size;

    // Map the guarded range to PROT_NONE
    let guard_addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            guarded_size,
            libc::PROT_NONE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };

    if guard_addr == libc::MAP_FAILED {
        return Err(MmapRegionError::Mmap(IoError::last_os_error()));
    }

    let (fd, offset) = if let Some(ref f_off) = file_offset {
        check_file_offset(f_off, size)?;
        (f_off.file().as_raw_fd(), f_off.start())
    } else {
        (-1, 0)
    };

    let map_addr = guard_addr as usize + page_size * (GUARD_NUMBER / 2);

    // Inside the protected range, starting with guard_addr + PAGE_SIZE,
    // map the requested range with received protection and flags
    let addr = unsafe {
        libc::mmap(
            map_addr as *mut libc::c_void,
            size,
            prot,
            flags | libc::MAP_FIXED,
            fd,
            offset as libc::off_t,
        )
    };

    if addr == libc::MAP_FAILED {
        return Err(MmapRegionError::Mmap(IoError::last_os_error()));
    }

    Ok(unsafe { MmapRegion::build_raw(addr as *mut u8, size, prot, flags)? })
}

pub fn create_guest_memory(
    regions: &[(Option<FileOffset>, GuestAddress, usize)],
    track_dirty_pages: bool,
) -> std::result::Result<GuestMemoryMmap, Error> {
    let guest_mem = GuestMemoryMmap::from_regions(
        regions
            .iter()
            .map(|region| {
                let flags = match region.0 {
                    None => libc::MAP_NORESERVE | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    Some(_) => libc::MAP_NORESERVE | libc::MAP_PRIVATE,
                };

                GuestRegionMmap::new(
                    build_guarded_region(
                        region.0.clone(),
                        region.2,
                        libc::PROT_READ | libc::PROT_WRITE,
                        flags,
                    )
                    .unwrap(),
                    region.1,
                )
                .unwrap()
            })
            .collect::<Vec<_>>(),
    )
    .unwrap();

    if track_dirty_pages {
        enable_dirty_page_tracking(&guest_mem);
    }

    Ok(guest_mem)
}
