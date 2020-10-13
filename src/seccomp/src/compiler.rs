use super::syscall_table::SyscallTable;
use seccomp::{
    BpfThreadMap, Error as SeccompFilterError, SeccompAction, SeccompCondition, SeccompFilter,
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

type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match *self {
            MultipleSyscallFields => write!(
                f,
                "Cannot use both `syscalls` and `syscall` properties in an object"
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
#[serde(deny_unknown_fields)]
pub(crate) struct SyscallObject {
    syscall: Option<String>,
    syscalls: Option<Vec<String>>,
    action: Option<SeccompAction>,
    #[serde(rename = "args")]
    conditions: Option<Vec<SeccompCondition>>,
    /// Unused field, represents a comment property in the JSON format
    #[allow(dead_code)]
    comment: Option<String>,
}

impl SyscallObject {
    pub fn new(
        syscall: Option<String>,
        syscalls: Option<Vec<String>>,
        action: Option<SeccompAction>,
        conditions: Option<Vec<SeccompCondition>>,
    ) -> SyscallObject {
        SyscallObject {
            syscall,
            syscalls,
            action,
            conditions,
            comment: None,
        }
    }
    fn is_singular(&self) -> bool {
        self.syscall.is_some() && self.syscalls.is_none()
    }

    fn is_plural(&self) -> bool {
        self.syscall.is_none() && self.syscalls.is_some()
    }

    // Perform semantic checks of the file format
    fn validate(&self) -> Result<()> {
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
}

// Each thread category maps to one of these
#[derive(Deserialize, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct Filter {
    default_action: SeccompAction,
    filter_action: SeccompAction,
    filter: Vec<SyscallObject>,
}

impl Filter {
    pub fn new(
        default_action: SeccompAction,
        filter_action: SeccompAction,
        filter: Vec<SyscallObject>,
    ) -> Filter {
        Filter {
            default_action,
            filter_action,
            filter,
        }
    }
    fn validate(&self) -> Result<()> {
        self.filter
            .iter()
            .map(|syscall_obj| syscall_obj.validate())
            .find(|result| result.is_err())
            .or_else(|| Some(Ok(())))
            .unwrap()
    }
}

pub(crate) struct Compiler {
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
    fn validate_filters(&self, filters: &HashMap<String, Filter>) -> Result<()> {
        filters
            .iter()
            .map(|(_, filter)| filter.validate())
            .find(|result| result.is_err())
            .or_else(|| Some(Ok(())))
            .unwrap()
    }

    pub fn compile_blob(&self, filters: HashMap<String, Filter>) -> Result<BpfThreadMap> {
        self.validate_filters(&filters)?;
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
    fn make_seccomp_filter(&self, filter: Filter) -> Result<SeccompFilter> {
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
        Error as SeccompFilterError, SeccompAction, SeccompCmpArgLen::*, SeccompCmpOp::*,
        SeccompCondition as Cond, SeccompFilter, SeccompRule, SyscallRuleSet,
    };
    use std::collections::HashMap;

    fn match_syscall(syscall_number: i64, action: SeccompAction) -> SyscallRuleSet {
        (syscall_number, vec![SeccompRule::new(vec![], action)])
    }

    fn match_syscall_if(syscall_number: i64, rules: Vec<SeccompRule>) -> SyscallRuleSet {
        (syscall_number, rules)
    }

    #[test]
    // test the transformation of Filter objects into SeccompFilter objects
    // we test this private method because we are interested in seeing that the
    // Filter -> SeccompFilter transformation is done correctly.
    fn test_make_seccomp_filter() {
        let compiler = Compiler::new(std::env::consts::ARCH);
        // test a well-formed filter. malformed filters are tested in test_compile_blob()
        // this data structure is deserialized from JSON
        let filter = Filter::new(
            SeccompAction::Trap,
            SeccompAction::Allow,
            vec![
                SyscallObject::new(
                    Some("SYS_open".to_string()),
                    None,
                    Some(SeccompAction::Log),
                    None,
                ),
                SyscallObject::new(
                    None,
                    Some(vec!["SYS_close".to_string(), "SYS_stat".to_string()]),
                    Some(SeccompAction::Trap),
                    None,
                ),
                SyscallObject::new(
                    Some("SYS_futex".to_string()),
                    None,
                    Some(SeccompAction::Log),
                    Some(vec![
                        Cond::new(2, DWORD, Le, 65).unwrap(),
                        Cond::new(1, QWORD, Ne, 80).unwrap(),
                    ]),
                ),
                SyscallObject::new(
                    Some("SYS_futex".to_string()),
                    None,
                    None,
                    Some(vec![
                        Cond::new(3, QWORD, Gt, 65).unwrap(),
                        Cond::new(1, QWORD, Lt, 80).unwrap(),
                    ]),
                ),
                SyscallObject::new(
                    Some("SYS_futex".to_string()),
                    None,
                    None,
                    Some(vec![Cond::new(3, QWORD, Ge, 65).unwrap()]),
                ),
                SyscallObject::new(
                    Some("SYS_ioctl".to_string()),
                    None,
                    None,
                    Some(vec![Cond::new(3, DWORD, MaskedEq(100), 65).unwrap()]),
                ),
            ],
        );

        // The expected IR
        let seccomp_filter = SeccompFilter::new(
            vec![
                match_syscall(
                    compiler.syscall_table.get_syscall_nr("SYS_open").unwrap(),
                    SeccompAction::Log,
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
                                Cond::new(2, DWORD, Le, 65).unwrap(),
                                Cond::new(1, QWORD, Ne, 80).unwrap(),
                            ],
                            SeccompAction::Log,
                        ),
                        SeccompRule::new(
                            vec![
                                Cond::new(3, QWORD, Gt, 65).unwrap(),
                                Cond::new(1, QWORD, Lt, 80).unwrap(),
                            ],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![Cond::new(3, QWORD, Ge, 65).unwrap()],
                            SeccompAction::Allow,
                        ),
                    ],
                ),
                match_syscall_if(
                    compiler.syscall_table.get_syscall_nr("SYS_ioctl").unwrap(),
                    vec![SeccompRule::new(
                        vec![Cond::new(3, DWORD, MaskedEq(100), 65).unwrap()],
                        SeccompAction::Allow,
                    )],
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
    }

    #[test]
    fn test_compile_blob() {
        let compiler = Compiler::new(std::env::consts::ARCH);
        // test with malformed filters
        let mut wrong_syscall_properties_filters = HashMap::new();
        wrong_syscall_properties_filters.insert(
            "t2".to_string(),
            Filter::new(
                SeccompAction::Trap,
                SeccompAction::Allow,
                vec![SyscallObject::new(
                    Some("SYS_open".to_string()),
                    Some(vec!["SYS_open".to_string()]),
                    None,
                    None,
                )],
            ),
        );

        assert_eq!(
            compiler.compile_blob(wrong_syscall_properties_filters),
            Err(Error::MultipleSyscallFields)
        );

        let mut syscalls_with_conditions_filters = HashMap::new();
        syscalls_with_conditions_filters.insert(
            "t2".to_string(),
            Filter::new(
                SeccompAction::Trap,
                SeccompAction::Allow,
                vec![SyscallObject::new(
                    None,
                    Some(vec!["SYS_close".to_string(), "SYS_read".to_string()]),
                    None,
                    Some(vec![Cond::new(3, DWORD, Eq, 65).unwrap()]),
                )],
            ),
        );

        assert_eq!(
            compiler.compile_blob(syscalls_with_conditions_filters),
            Err(Error::SyscallsWithArgs(vec![
                "SYS_close".to_string(),
                "SYS_read".to_string()
            ]))
        );

        let mut wrong_syscall_name_filters = HashMap::new();
        wrong_syscall_name_filters.insert(
            "T1".to_string(),
            Filter::new(
                SeccompAction::Trap,
                SeccompAction::Allow,
                vec![SyscallObject::new(
                    Some("wrong_syscall".to_string()),
                    None,
                    None,
                    None,
                )],
            ),
        );

        assert_eq!(
            compiler.compile_blob(wrong_syscall_name_filters),
            Err(Error::SyscallName(
                "wrong_syscall".to_string(),
                compiler.arch.clone()
            ))
        );

        // test with correct filters
        let mut correct_filters = HashMap::new();
        correct_filters.insert(
            "Thread1".to_string(),
            Filter::new(
                SeccompAction::Trap,
                SeccompAction::Allow,
                vec![
                    SyscallObject::new(Some("SYS_open".to_string()), None, None, None),
                    SyscallObject::new(
                        None,
                        Some(vec!["SYS_close".to_string(), "SYS_stat".to_string()]),
                        Some(SeccompAction::Trap),
                        None,
                    ),
                    SyscallObject::new(
                        Some("SYS_futex".to_string()),
                        None,
                        None,
                        Some(vec![
                            Cond::new(1, DWORD, Eq, 65).unwrap(),
                            Cond::new(2, QWORD, Le, 80).unwrap(),
                        ]),
                    ),
                    SyscallObject::new(
                        Some("SYS_futex".to_string()),
                        None,
                        None,
                        Some(vec![
                            Cond::new(3, DWORD, Eq, 65).unwrap(),
                            Cond::new(2, QWORD, Le, 80).unwrap(),
                        ]),
                    ),
                ],
            ),
        );

        // We don't test the BPF compilation in this module.
        // This is done in the seccomp/lib.rs module.
        // Here, we only test the Filter->SeccompFilter transformations.
        assert!(compiler.compile_blob(correct_filters).is_ok());
    }

    #[test]
    fn test_error_messages() {
        assert_eq!(
            format!("{}", Error::MultipleSyscallFields),
            "Cannot use both `syscalls` and `syscall` properties in an object"
        );
        assert_eq!(
            format!(
                "{}",
                Error::SeccompFilter(SeccompFilterError::InvalidArgumentNumber)
            ),
            "The seccomp rule contains an invalid argument number."
        );
        assert_eq!(
            format!(
                "{}",
                Error::SyscallName("SYS_asdsad".to_string(), "x86_64".to_string())
            ),
            format!(
                "Invalid syscall name: {} for given arch: {}",
                "SYS_asdsad", "x86_64"
            )
        );
        assert_eq!(
            format!(
                "{}",
                Error::SyscallsWithArgs(vec!["SYS_close".to_string(), "SYS_open".to_string()])
            ),
            format!(
                "The object with the following `syscalls`: {:?} cannot have argument\
                 conditions. Use the `syscall` property instead or remove the `args` property.",
                vec!["SYS_close".to_string(), "SYS_open".to_string()]
            )
        );
    }
}
