// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use seccomp::{BpfProgram, SeccompError, SeccompLevel};

/// Retrieve a BPF program based on a seccomp level value.
pub fn get_seccomp_filter(seccomp_level: SeccompLevel) -> Result<BpfProgram, SeccompError> {
    match seccomp_level {
        SeccompLevel::None => Ok(vec![]),
        SeccompLevel::Basic => Ok(vec![]),
        SeccompLevel::Advanced => Ok(vec![]),
    }
}

#[cfg(test)]
mod tests {
    use super::get_seccomp_filter;
    use seccomp::SeccompLevel;

    #[test]
    fn test_get_seccomp_filter() {
        assert!(get_seccomp_filter(SeccompLevel::None).is_ok());
        assert!(get_seccomp_filter(SeccompLevel::Basic).is_ok());
        assert!(get_seccomp_filter(SeccompLevel::Advanced).is_ok());
    }
}
