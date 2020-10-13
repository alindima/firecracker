// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use seccomp::{BpfThreadMap, SeccompError, SeccompLevel};
use std::collections::HashMap;

fn empty_filters() -> BpfThreadMap {
    let mut map = HashMap::new();
    map.insert("Vmm".to_string(), vec![]);
    map.insert("Api".to_string(), vec![]);
    map.insert("Vcpu".to_string(), vec![]);
    map
}

/// Retrieve the BPF programs based on a seccomp level value.
pub fn get_seccomp_filters(seccomp_level: SeccompLevel) -> Result<BpfThreadMap, SeccompError> {
    match seccomp_level {
        SeccompLevel::None => Ok(empty_filters()), // empty filters
        SeccompLevel::Advanced => Ok(empty_filters()), // get the hardcoded filter
        SeccompLevel::File(_) => Ok(empty_filters()), // read from file
    }
}

#[cfg(test)]
mod tests {
    use super::get_seccomp_filters;
    use seccomp::SeccompLevel;

    #[test]
    fn test_get_seccomp_filters() {
        assert!(get_seccomp_filters(SeccompLevel::None).is_ok());
        assert!(get_seccomp_filters(SeccompLevel::Advanced).is_ok());
        assert!(get_seccomp_filters(SeccompLevel::File("path".to_string())).is_ok());
    }
}
