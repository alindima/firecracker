// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

pub use vm_memory_upstream::{
    address, bitmap::Bitmap, mmap::MmapRegionBuilder, mmap::MmapRegionError, Address, ByteValued,
    Bytes, Error, FileOffset, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryRegion,
    GuestUsize, MemoryRegionAddress,
};

use std::io::Error as IoError;
use std::os::unix::io::AsRawFd;

use vm_memory_upstream::bitmap::AtomicBitmap;
use vm_memory_upstream::mmap::{check_file_offset, NewBitmap};
use vm_memory_upstream::{
    GuestMemoryMmap as UpstreamGuestMemoryMmap, GuestRegionMmap as UpstreamGuestRegionMmap,
    MmapRegion as UpstreamMmapRegion,
};

pub type GuestMemoryMmap = UpstreamGuestMemoryMmap<Option<AtomicBitmap>>;
pub type GuestRegionMmap = UpstreamGuestRegionMmap<Option<AtomicBitmap>>;
pub type MmapRegion = UpstreamMmapRegion<Option<AtomicBitmap>>;

const GUARD_NUMBER: usize = 2;

/// Build a MmapRegion surrounded by guard pages.
fn build_guarded_region(
    file_offset: Option<FileOffset>,
    size: usize,
    prot: i32,
    flags: i32,
    track_dirty_pages: bool,
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

    let bitmap = match track_dirty_pages {
        true => Some(AtomicBitmap::with_len(size)),
        false => None,
    };

    unsafe {
        MmapRegionBuilder::new_with_bitmap(size, bitmap)
            .with_raw_mmap_pointer(addr as *mut u8)
            .with_mmap_prot(prot)
            .with_mmap_flags(flags)
            .build()
    }
}

/// Helper for creating the guest memory.
pub fn create_guest_memory(
    regions: &[(Option<FileOffset>, GuestAddress, usize)],
    track_dirty_pages: bool,
) -> std::result::Result<GuestMemoryMmap, Error> {
    let prot = libc::PROT_READ | libc::PROT_WRITE;
    let mut mmap_regions = Vec::with_capacity(regions.len());

    for region in regions {
        let flags = match region.0 {
            None => libc::MAP_NORESERVE | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            Some(_) => libc::MAP_NORESERVE | libc::MAP_PRIVATE,
        };

        let mmap_region =
            build_guarded_region(region.0.clone(), region.2, prot, flags, track_dirty_pages)
                .map_err(Error::MmapRegion)?;

        mmap_regions.push(GuestRegionMmap::new(mmap_region, region.1)?);
    }

    GuestMemoryMmap::from_regions(mmap_regions)
}

pub mod test_utils {
    use super::*;

    /// Test helper used to initialize the guest memory without adding guard pages.
    /// This is needed because the default `create_guest_memory`
    /// uses MmapRegionBuilder::build_raw() for setting up the memory with guard pages, which would
    /// error if the size is not a multiple of the page size.
    /// There are unit tests which need a custom memory size, not a multiple of the page size.
    pub fn create_guest_memory_unguarded(
        regions: &[(GuestAddress, usize)],
        track_dirty_pages: bool,
    ) -> std::result::Result<GuestMemoryMmap, Error> {
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let flags = libc::MAP_NORESERVE | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
        let mut mmap_regions = Vec::with_capacity(regions.len());

        for region in regions {
            mmap_regions.push(GuestRegionMmap::new(
                MmapRegionBuilder::new_with_bitmap(
                    region.1,
                    match track_dirty_pages {
                        true => Some(AtomicBitmap::with_len(region.1)),
                        false => None,
                    },
                )
                .with_mmap_prot(prot)
                .with_mmap_flags(flags)
                .build()
                .map_err(Error::MmapRegion)?,
                region.0,
            )?);
        }
        GuestMemoryMmap::from_regions(mmap_regions)
    }
}
