use super::syscall_table::SyscallTable;
use seccomp::{
    BpfProgram, SeccompAction, SeccompCondition, SeccompFilter, SeccompRule, SeccompRuleMap,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::convert::TryInto;
use std::io::Read;
use std::result::Result;

#[derive(Debug, Deserialize, PartialEq)]
struct SyscallObject {
    syscall: Option<String>,
    syscalls: Option<Vec<String>>,
    action: Option<SeccompAction>,
    #[serde(rename = "args")]
    conditions: Option<Vec<SeccompCondition>>,
}

impl SyscallObject {
    pub fn is_singular(&self) -> bool {
        self.syscall.is_some() && self.syscalls.is_none()
    }

    pub fn is_plural(&self) -> bool {
        self.syscall.is_none() && self.syscalls.is_some()
    }

    // implement validation of fields -> validate the existence of args field and singular/plural
    // pub fn validate(&self) -> Result<(), >
}

// Each thread category maps to one of these
#[derive(Deserialize, PartialEq, Debug)]
struct Filter {
    default_action: SeccompAction,
    filter_action: SeccompAction,
    filter: Vec<SyscallObject>,
}

#[derive(Debug)]
pub struct Parser {
    // map from thread category to filter object
    filters: HashMap<String, Filter>,

    syscall_table: SyscallTable,
}

impl Parser {
    // Deserializes the filter data from a Read object
    pub fn new(arch: &str, reader: &mut dyn Read) -> Self {
        Self {
            filters: serde_json::from_reader(reader).unwrap(),
            syscall_table: SyscallTable::new(arch.to_string()),
        }
    }

    pub fn generate_blob(&self) -> HashMap<String, BpfProgram> {
        self.filters
            .iter()
            .map(|(thread_name, filter)| (thread_name.clone(), self.compile_bpf_filter(filter)))
            .collect()
    }
    // TODO: refactor control flow & nesting levels, error checking
    // compiles a filter for a given thread
    // internal: create SeccompFilter for the given thread & cast it to BPFProgram
    fn compile_bpf_filter(&self, filter: &Filter) -> BpfProgram {
        let mut rule_map: SeccompRuleMap = SeccompRuleMap::new();

        for syscall_object in &filter.filter {
            let action = syscall_object
                .action
                .clone()
                .or(Some(filter.filter_action.clone()))
                .unwrap();
            if syscall_object.is_plural() {
                for syscall in syscall_object.syscalls.as_ref().unwrap() {
                    let syscall_nr = self.syscall_table.get_syscall_nr(&syscall).unwrap();
                    let rule_accumulator = rule_map.entry(syscall_nr).or_insert(vec![]);

                    rule_accumulator.push(SeccompRule::new(vec![], action.clone()));
                }
            } else if syscall_object.is_singular() {
                let syscall_nr = self
                    .syscall_table
                    .get_syscall_nr(syscall_object.syscall.as_ref().unwrap())
                    .unwrap();
                let rule_accumulator = rule_map.entry(syscall_nr).or_insert(vec![]);
                let conditions = syscall_object.conditions.clone().or(Some(vec![])).unwrap();

                rule_accumulator.push(SeccompRule::new(conditions, action));
            }
        }

        // TODO: check for conflicting rules before returning

        SeccompFilter::new(rule_map, filter.default_action.clone())
            .unwrap()
            .try_into()
            .unwrap()
    }
}
