use super::syscall_table::SyscallTable;
use seccomp::{
    BpfProgram, Error as SeccompFilterError, SeccompAction, SeccompCondition, SeccompFilter,
    SeccompRule, SeccompRuleMap,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Deserialize, PartialEq)]
struct SyscallObject {
    syscall: Option<String>,
    syscalls: Option<Vec<String>>,
    action: Option<SeccompAction>,
    #[serde(rename = "args")]
    conditions: Option<Vec<SeccompCondition>>,
}

#[derive(Debug)]
pub enum Error {
    MultipleSyscallFields,
    SeccompFilter(SeccompFilterError),
    SyscallName(String, String),
    SyscallsWithArgs(Vec<String>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match *self {
            MultipleSyscallFields => write!(
                f,
                "Invalid use of both `syscalls` and `syscall` properties in an object"
            ),
            SeccompFilter(ref err) => write!(f, "{}", err),
            SyscallName(ref syscall_name, ref arch) => write!(
                f,
                "Invalid syscall name: {} for given arch: {}",
                syscall_name, arch
            ),
            SyscallsWithArgs(ref syscalls) => write!(
                f,
                "The object with the following `syscalls`: {:?} cannot have argument\
                 conditions. Use the `syscall` property instead or remove the `args` property.",
                syscalls
            ),
        }
    }
}

impl SyscallObject {
    pub fn is_singular(&self) -> bool {
        self.syscall.is_some() && self.syscalls.is_none()
    }

    pub fn is_plural(&self) -> bool {
        self.syscall.is_none() && self.syscalls.is_some()
    }

    // Perform semantic checks of the file format
    pub fn validate(&self) -> Result<(), Error> {
        if self.syscall.is_some() && self.syscalls.is_some() {
            return Err(Error::MultipleSyscallFields);
        }

        if self.is_plural() && self.conditions.is_some() {
            return Err(Error::SyscallsWithArgs(
                // safe to unwrap because self.is_plural() == true
                self.syscalls.as_ref().unwrap().clone(),
            ));
        }

        Ok(())
    }
}

// Each thread category maps to one of these
#[derive(Deserialize, PartialEq, Debug)]
pub struct Filter {
    default_action: SeccompAction,
    filter_action: SeccompAction,
    filter: Vec<SyscallObject>,
}

impl Filter {
    pub fn validate(&self) -> Result<(), Error> {
        self.filter
            .iter()
            .map(|syscall_obj| syscall_obj.validate())
            .find(|result| result.is_err())
            .or_else(|| Some(Ok(())))
            .unwrap()
    }
}

#[derive(Debug)]
pub struct Compiler {
    arch: String,
    syscall_table: SyscallTable,
}

impl Compiler {
    // Deserializes the filter data from a Read object
    pub fn new(arch: &str) -> Self {
        Self {
            arch: arch.to_string(),
            syscall_table: SyscallTable::new(arch.to_string()),
        }
    }

    // Perform semantic checks of the file format
    pub fn validate_filters(&self, filters: &HashMap<String, Filter>) -> Result<(), Error> {
        filters
            .iter()
            .map(|(_, filter)| filter.validate())
            .find(|result| result.is_err())
            .or_else(|| Some(Ok(())))
            .unwrap()
    }

    pub fn compile_blob(
        &self,
        filters: HashMap<String, Filter>,
    ) -> Result<HashMap<String, BpfProgram>, Error> {
        let mut bpf_map = HashMap::new();

        for (thread_name, filter) in filters.into_iter() {
            bpf_map.insert(
                thread_name,
                self.make_seccomp_filter(filter)?
                    .into_bpf(&self.arch)
                    .map_err(Error::SeccompFilter)?,
            );
        }
        Ok(bpf_map)
    }
    // Transforms a Filter (IR) into a SeccompFilter
    fn make_seccomp_filter(&self, filter: Filter) -> Result<SeccompFilter, Error> {
        let mut rule_map: SeccompRuleMap = SeccompRuleMap::new();

        for syscall_object in filter.filter {
            let filter_action = &filter.filter_action;

            if syscall_object.is_plural() {
                let action = syscall_object
                    .action
                    .or_else(|| Some(filter_action.clone()))
                    // safe to unwrap because of the or_else
                    .unwrap();
                // safe to unwrap syscall_object.syscalls because syscall_object.is_plural() == true
                for syscall in syscall_object.syscalls.as_ref().unwrap() {
                    let syscall_nr = self
                        .syscall_table
                        .get_syscall_nr(syscall)
                        .ok_or_else(|| Error::SyscallName(syscall.clone(), self.arch.clone()))?;
                    let rule_accumulator = rule_map.entry(syscall_nr).or_insert_with(|| vec![]);

                    rule_accumulator.push(SeccompRule::new(vec![], action.clone()));
                }
            } else if syscall_object.is_singular() {
                // safe to unwrap syscall_object.syscalls because syscall_object.is_plural() == true
                let syscall = syscall_object.syscall.as_ref().unwrap();
                let action = syscall_object
                    .action
                    .or_else(|| Some(filter_action.clone()))
                    // safe to unwrap because of the or_else
                    .unwrap();
                let syscall_nr = self
                    .syscall_table
                    .get_syscall_nr(syscall)
                    .ok_or_else(|| Error::SyscallName(syscall.clone(), self.arch.clone()))?;
                let rule_accumulator = rule_map.entry(syscall_nr).or_insert_with(|| vec![]);
                let conditions = syscall_object
                    .conditions
                    .or_else(|| Some(vec![]))
                    // safe to unwrap because of the or_else
                    .unwrap();

                rule_accumulator.push(SeccompRule::new(conditions, action));
            }
        }

        SeccompFilter::new(rule_map, filter.default_action).map_err(Error::SeccompFilter)
    }
}

#[cfg(test)]
mod tests {
    // use super::Compiler;

    // add helpers for creating Filter objects

    #[test]
    fn test_make_seccomp_filter() {
        // test the transformation of Filter objects into SeccompFilters
    }
}
