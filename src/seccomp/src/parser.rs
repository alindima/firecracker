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
    rules: Option<Vec<SeccompCondition>>,
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
            // multiple syscalls
            if syscall_object.syscalls.is_some() && syscall_object.syscall.is_none() {
                for syscall in syscall_object.syscalls.as_ref().unwrap() {
                    let syscall_nr = self.syscall_table.get_syscall_nr(&syscall).unwrap();
                    let rule_accumulator = rule_map.entry(syscall_nr).or_insert(vec![]);

                    if syscall_object.action.is_some() {
                        // overriding the filter_action
                        rule_accumulator.push(SeccompRule::new(
                            vec![],
                            syscall_object.action.as_ref().unwrap().clone(),
                        ));
                    } else {
                        // adding the default filter_action to the rule
                        rule_accumulator
                            .push(SeccompRule::new(vec![], filter.filter_action.clone()));
                    }
                }
            }
            // single syscall
            else if syscall_object.syscall.is_some() && syscall_object.syscalls.is_none() {
                let syscall_nr = self
                    .syscall_table
                    .get_syscall_nr(syscall_object.syscall.as_ref().unwrap())
                    .unwrap();
                let rule_accumulator = rule_map.entry(syscall_nr).or_insert(vec![]);
                if syscall_object.action.is_some() {
                    // overriding the filter_action
                    if (syscall_object.rules.is_some()) {
                        rule_accumulator.push(SeccompRule::new(
                            syscall_object.rules.as_ref().unwrap().clone(),
                            syscall_object.action.as_ref().unwrap().clone(),
                        ));
                    } else {
                        rule_accumulator.push(SeccompRule::new(
                            vec![],
                            syscall_object.action.as_ref().unwrap().clone(),
                        ));
                    }
                } else {
                    // adding the default filter_action to the rule
                    if (syscall_object.rules.is_some()) {
                        rule_accumulator.push(SeccompRule::new(
                            syscall_object.rules.as_ref().unwrap().clone(),
                            filter.filter_action.clone(),
                        ));
                    } else {
                        rule_accumulator
                            .push(SeccompRule::new(vec![], filter.filter_action.clone()));
                    }
                }
            }
        }

        // TODO: check for conflicting rules before returning

        SeccompFilter::new(rule_map, filter.default_action.clone())
            .unwrap()
            .try_into()
            .unwrap()
    }
}
