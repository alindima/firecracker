// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use seccomp::{deserialize_binary, BpfThreadMap, DeserializationError, Error};
use std::fmt;
use std::fs::File;

const THREAD_CATEGORIES: [&str; 3] = ["vmm", "api", "vcpu"];

/// Error retrieving seccomp filters.
#[derive(fmt::Debug)]
pub enum FilterError {
    /// Filter deserialitaion error.
    Deserialization(DeserializationError),
    /// Invalid thread categories.
    ThreadCategories(String),
    /// Missing Thread Category.
    MissingThreadCategory(String),
    /// Seccomp error occurred.
    Seccomp(Error),
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::FilterError::*;

        match *self {
            Deserialization(ref err) => write!(f, "Filter (de)serialization failed: {}", err),
            ThreadCategories(ref categories) => {
                write!(f, "Invalid thread categories: {}", categories)
            }
            MissingThreadCategory(ref category) => {
                write!(f, "Missing thread category: {}", category)
            }
            Seccomp(ref err) => write!(f, "Seccomp error: {}", err),
        }
    }
}

/// Return an error if the BpfThreadMap contains invalid thread categories.
fn filter_thread_categories(map: BpfThreadMap) -> Result<BpfThreadMap, FilterError> {
    let (filters, invalid_filters): (BpfThreadMap, BpfThreadMap) = map
        .into_iter()
        .partition(|(k, _)| THREAD_CATEGORIES.contains(&k.as_str()));
    if !invalid_filters.is_empty() {
        // build the error message
        let mut thread_categories_string =
            invalid_filters
                .keys()
                .fold("".to_string(), |mut acc, elem| {
                    acc.push_str(elem);
                    acc.push_str(",");
                    acc
                });
        thread_categories_string.pop();
        return Err(FilterError::ThreadCategories(thread_categories_string));
    }

    for &category in THREAD_CATEGORIES.iter() {
        let category_string = category.to_string();
        if !filters.contains_key(&category_string) {
            return Err(FilterError::MissingThreadCategory(category_string));
        }
    }

    Ok(filters)
}

/// Retrieve the default filters containing the syscall rules required by `Firecracker`
/// to function. The binary file is generated via the `build.rs` script of this crate.
pub fn get_default_filters() -> Result<BpfThreadMap, FilterError> {
    // Retrieve, at compile-time, the serialized binary filter generated with seccompiler.
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/seccomp_filter.bpf"));
    let map = deserialize_binary(&mut &bytes[..]).map_err(FilterError::Deserialization)?;
    filter_thread_categories(map)
}

/// Retrieve empty seccomp filters.
pub fn get_empty_filters() -> BpfThreadMap {
    let mut map = BpfThreadMap::new();
    map.insert("vmm".to_string(), vec![]);
    map.insert("api".to_string(), vec![]);
    map.insert("vcpu".to_string(), vec![]);
    map
}

/// Retrieve custom seccomp filters.
pub fn get_custom_filters(mut file: File) -> Result<BpfThreadMap, FilterError> {
    let map = deserialize_binary(&mut file).map_err(FilterError::Deserialization)?;
    filter_thread_categories(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seccomp::BpfThreadMap;

    #[test]
    fn test_get_default_filters() {
        // assert!(get_default_filters().is_ok());
    }

    #[test]
    fn test_get_empty_filters() {
        assert!(filter_thread_categories(get_empty_filters()).is_ok());
    }

    #[test]
    fn test_filter_thread_categories() {
        // correct categories
        let mut map = BpfThreadMap::new();
        map.insert("vcpu".to_string(), vec![]);
        map.insert("vmm".to_string(), vec![]);
        map.insert("api".to_string(), vec![]);

        assert_eq!(filter_thread_categories(map).unwrap().len(), 3);

        // invalid categories
        let mut map = BpfThreadMap::new();
        map.insert("vcpu".to_string(), vec![]);
        map.insert("vmm".to_string(), vec![]);
        map.insert("thread1".to_string(), vec![]);
        map.insert("thread2".to_string(), vec![]);

        match filter_thread_categories(map).unwrap_err() {
            FilterError::ThreadCategories(err) => {
                assert!(err == "thread2,thread1" || err == "thread1,thread2")
            }
            _ => panic!("Expected ThreadCategories error."),
        }

        // missing category
        let mut map = BpfThreadMap::new();
        map.insert("vcpu".to_string(), vec![]);
        map.insert("vmm".to_string(), vec![]);

        match filter_thread_categories(map).unwrap_err() {
            FilterError::MissingThreadCategory(name) => assert_eq!(name, "api"),
            _ => panic!("Expected MissingThreadCategory error."),
        }
    }
}
