use super::syscall_table::SyscallTable;
use seccomp::{
    BpfProgram, Error as SeccompFilterError, SeccompAction, SeccompCondition, SeccompFilter,
    SeccompRule, SeccompRuleMap,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, PartialEq)]
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

        if self.conditions.is_some() {
            for condition in self.conditions.as_ref().unwrap().iter() {
                if let Err(err) = condition.validate() {
                    return Err(Error::SeccompFilter(err));
                }
            }
        }

        Ok(())
    }

    // add method transform_into_seccomp_rules
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
    // Transforms a Filter into a SeccompFilter (IR)
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
    use super::{Compiler, Error, Filter, SyscallObject};
    use seccomp::{
        SeccompAction, SeccompCmpArgLen::*, SeccompCmpOp::*, SeccompCondition as Cond,
        SeccompFilter, SeccompRule, SyscallRuleSet,
    };
    use std::collections::HashMap;

    fn match_syscall(syscall_number: i64, action: SeccompAction) -> SyscallRuleSet {
        (syscall_number, vec![SeccompRule::new(vec![], action)])
    }

    fn match_syscall_if(syscall_number: i64, rules: Vec<SeccompRule>) -> SyscallRuleSet {
        (syscall_number, rules)
    }

    fn empty_syscall_object() -> SyscallObject {
        SyscallObject {
            syscall: None,
            syscalls: None,
            conditions: None,
            action: None,
        }
    }

    #[test]
    fn test_syscall_object_methods() {
        let syscall_object1 = SyscallObject {
            syscall: Some("SYS_futex".to_string()),
            conditions: Some(vec![
                Cond::new(1, DWORD, Eq, 65).unwrap(),
                Cond::new(2, QWORD, Le, 80).unwrap(),
            ]),
            ..empty_syscall_object()
        };

        assert!(syscall_object1.is_singular());
        assert!(!syscall_object1.is_plural());

        let syscall_object2 = SyscallObject {
            syscalls: Some(vec!["SYS_close".to_string(), "SYS_stat".to_string()]),
            action: Some(SeccompAction::Trap),
            ..empty_syscall_object()
        };

        assert!(syscall_object2.is_plural());
        assert!(!syscall_object2.is_singular());
    }

    #[test]
    fn test_validate_syscall_object() {
        // valid syscall objects
        let syscall_object1 = SyscallObject {
            syscall: Some("SYS_futex".to_string()),
            conditions: Some(vec![
                Cond::new(1, DWORD, Eq, 65).unwrap(),
                Cond::new(2, QWORD, Le, 80).unwrap(),
            ]),
            ..empty_syscall_object()
        };

        let syscall_object2 = SyscallObject {
            syscall: Some("SYS_open".to_string()),
            ..empty_syscall_object()
        };

        let syscall_object3 = SyscallObject {
            syscalls: Some(vec!["SYS_close".to_string(), "SYS_stat".to_string()]),
            action: Some(SeccompAction::Trap),
            ..empty_syscall_object()
        };

        assert!(syscall_object1.validate().is_ok());
        assert!(syscall_object2.validate().is_ok());
        assert!(syscall_object3.validate().is_ok());

        // test malformed syscall objects
        let wrong_syscall_properties = SyscallObject {
            syscall: Some("SYS_open".to_string()),
            syscalls: Some(vec!["SYS_close".to_string(), "SYS_read".to_string()]),
            ..empty_syscall_object()
        };

        assert_eq!(
            wrong_syscall_properties.validate(),
            Err(Error::MultipleSyscallFields)
        );

        let syscalls_with_args = SyscallObject {
            syscalls: Some(vec!["SYS_close".to_string(), "SYS_read".to_string()]),
            conditions: Some(vec![Cond::new(3, DWORD, Eq, 65).unwrap()]),
            ..empty_syscall_object()
        };

        assert_eq!(
            syscalls_with_args.validate(),
            Err(Error::SyscallsWithArgs(vec![
                "SYS_close".to_string(),
                "SYS_read".to_string()
            ]))
        );
    }

    #[test]
    fn test_validate_filter() {
        // test correctly formed filter
        let correct_filter = Filter {
            default_action: SeccompAction::Trap,
            filter_action: SeccompAction::Allow,
            filter: vec![
                SyscallObject {
                    syscall: Some("SYS_open".to_string()),
                    ..empty_syscall_object()
                },
                SyscallObject {
                    syscalls: Some(vec!["SYS_close".to_string(), "SYS_stat".to_string()]),
                    action: Some(SeccompAction::Trap),
                    ..empty_syscall_object()
                },
                SyscallObject {
                    syscall: Some("SYS_futex".to_string()),
                    conditions: Some(vec![
                        Cond::new(1, DWORD, Eq, 65).unwrap(),
                        Cond::new(2, QWORD, Le, 80).unwrap(),
                    ]),
                    ..empty_syscall_object()
                },
                SyscallObject {
                    syscall: Some("SYS_futex".to_string()),
                    conditions: Some(vec![
                        Cond::new(3, DWORD, Eq, 65).unwrap(),
                        Cond::new(2, QWORD, Le, 80).unwrap(),
                    ]),
                    ..empty_syscall_object()
                },
            ],
        };
        assert!(correct_filter.validate().is_ok());

        // test malformed filters
        let wrong_syscall_object_filter = Filter {
            default_action: SeccompAction::Trap,
            filter_action: SeccompAction::Allow,
            filter: vec![SyscallObject {
                syscall: Some("SYS_open".to_string()),
                syscalls: Some(vec!["SYS_close".to_string(), "SYS_read".to_string()]),
                ..empty_syscall_object()
            }],
        };

        assert_eq!(
            wrong_syscall_object_filter.validate(),
            Err(Error::MultipleSyscallFields)
        );

        let syscalls_with_args_filter = Filter {
            default_action: SeccompAction::Trap,
            filter_action: SeccompAction::Allow,
            filter: vec![SyscallObject {
                syscalls: Some(vec!["SYS_close".to_string(), "SYS_read".to_string()]),
                conditions: Some(vec![Cond::new(3, DWORD, Eq, 65).unwrap()]),
                ..empty_syscall_object()
            }],
        };

        assert_eq!(
            syscalls_with_args_filter.validate(),
            Err(Error::SyscallsWithArgs(vec![
                "SYS_close".to_string(),
                "SYS_read".to_string()
            ]))
        );
    }

    #[test]
    fn test_validate_filters() {
        let compiler = Compiler::new(std::env::consts::ARCH);

        // test with correct filters
        let mut correct_filters = HashMap::new();
        correct_filters.insert(
            "t1".to_string(),
            Filter {
                default_action: SeccompAction::Trap,
                filter_action: SeccompAction::Allow,
                filter: vec![SyscallObject {
                    syscalls: Some(vec!["SYS_close".to_string(), "SYS_stat".to_string()]),
                    action: Some(SeccompAction::Trap),
                    ..empty_syscall_object()
                }],
            },
        );
        correct_filters.insert(
            "t2".to_string(),
            Filter {
                default_action: SeccompAction::Trap,
                filter_action: SeccompAction::Allow,
                filter: vec![SyscallObject {
                    syscall: Some("SYS_open".to_string()),
                    ..empty_syscall_object()
                }],
            },
        );

        assert!(compiler.validate_filters(&correct_filters).is_ok());

        // test with malformed filters
        let mut malformed_filters = HashMap::new();
        malformed_filters.insert(
            "t1".to_string(),
            Filter {
                default_action: SeccompAction::Trap,
                filter_action: SeccompAction::Allow,
                filter: vec![SyscallObject {
                    syscalls: Some(vec!["SYS_close".to_string(), "SYS_stat".to_string()]),
                    action: Some(SeccompAction::Trap),
                    ..empty_syscall_object()
                }],
            },
        );
        malformed_filters.insert(
            "t2".to_string(),
            Filter {
                default_action: SeccompAction::Trap,
                filter_action: SeccompAction::Allow,
                filter: vec![SyscallObject {
                    syscall: Some("SYS_open".to_string()),
                    syscalls: Some(vec!["SYS_open".to_string()]),
                    ..empty_syscall_object()
                }],
            },
        );

        assert!(compiler.validate_filters(&malformed_filters).is_err());
    }

    #[test]
    // test the transformation of Filter objects into SeccompFilter objects
    fn test_make_seccomp_filter() {
        let compiler = Compiler::new(std::env::consts::ARCH);
        // test a correct filter
        let filter = Filter {
            default_action: SeccompAction::Trap,
            filter_action: SeccompAction::Allow,
            filter: vec![
                SyscallObject {
                    syscall: Some("SYS_open".to_string()),
                    ..empty_syscall_object()
                },
                SyscallObject {
                    syscalls: Some(vec!["SYS_close".to_string(), "SYS_stat".to_string()]),
                    action: Some(SeccompAction::Trap),
                    ..empty_syscall_object()
                },
                SyscallObject {
                    syscall: Some("SYS_futex".to_string()),
                    conditions: Some(vec![
                        Cond::new(1, DWORD, Eq, 65).unwrap(),
                        Cond::new(2, QWORD, Le, 80).unwrap(),
                    ]),
                    ..empty_syscall_object()
                },
                SyscallObject {
                    syscall: Some("SYS_futex".to_string()),
                    conditions: Some(vec![
                        Cond::new(3, DWORD, Eq, 65).unwrap(),
                        Cond::new(2, QWORD, Le, 80).unwrap(),
                    ]),
                    ..empty_syscall_object()
                },
            ],
        };

        let seccomp_filter = SeccompFilter::new(
            vec![
                match_syscall(
                    compiler.syscall_table.get_syscall_nr("SYS_open").unwrap(),
                    SeccompAction::Allow,
                ),
                match_syscall(
                    compiler.syscall_table.get_syscall_nr("SYS_close").unwrap(),
                    SeccompAction::Trap,
                ),
                match_syscall(
                    compiler.syscall_table.get_syscall_nr("SYS_stat").unwrap(),
                    SeccompAction::Trap,
                ),
                match_syscall_if(
                    compiler.syscall_table.get_syscall_nr("SYS_futex").unwrap(),
                    vec![
                        SeccompRule::new(
                            vec![
                                Cond::new(1, DWORD, Eq, 65).unwrap(),
                                Cond::new(2, QWORD, Le, 80).unwrap(),
                            ],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![
                                Cond::new(3, DWORD, Eq, 65).unwrap(),
                                Cond::new(2, QWORD, Le, 80).unwrap(),
                            ],
                            SeccompAction::Allow,
                        ),
                    ],
                ),
            ]
            .into_iter()
            .collect(),
            SeccompAction::Trap,
        )
        .unwrap();

        assert_eq!(
            compiler.make_seccomp_filter(filter).unwrap(),
            seccomp_filter
        );

        // filter with wrong syscall names
        let wrong_syscall_name_filter = Filter {
            default_action: SeccompAction::Trap,
            filter_action: SeccompAction::Allow,
            filter: vec![SyscallObject {
                syscall: Some("wrong_syscall".to_string()),
                ..empty_syscall_object()
            }],
        };

        assert_eq!(
            compiler.make_seccomp_filter(wrong_syscall_name_filter),
            Err(Error::SyscallName(
                "wrong_syscall".to_string(),
                compiler.arch.clone()
            ))
        );
    }
}
