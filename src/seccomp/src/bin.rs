// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(missing_docs)]

mod compiler;
mod syscall_table;

use bincode::Error as BincodeError;
use compiler::{Compiler, Error as FilterFormatError, Filter};
use seccomp::BpfProgram;
use serde_json::error::Error as JSONError;
use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::process;
use utils::arg_parser::{ArgParser, Argument, Arguments as ArgumentsBag};

const SECCOMPILER_VERSION: &str = env!("CARGO_PKG_VERSION");

const SUPPORTED_ARCHES: [&str; 2] = ["x86_64", "aarch64"];

#[derive(Debug)]
pub enum Error {
    Bincode(BincodeError),
    FileOpen(PathBuf, io::Error),
    FileFormat(FilterFormatError),
    InvalidArch,
    JSONError(JSONError),
    MissingInputFile,
}

type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match *self {
            Bincode(ref err) => write!(f, "Bincode (de)serialization failed: {}", err),
            FileFormat(ref err) => write!(f, "{}", err),
            FileOpen(ref path, ref err) => write!(
                f,
                "{}",
                format!("Failed to open file {:?}: {}", path, err).replace("\"", "")
            ),
            InvalidArch => write!(f, "Invalid arch"),
            JSONError(ref err) => write!(f, "Error parsing JSON: {}", err),
            MissingInputFile => write!(f, "Missing input file"),
        }
    }
}

#[derive(Debug, PartialEq)]
struct Arguments {
    input_file: String,
    output_file: String,
    target_arch: String,
}

fn build_arg_parser() -> ArgParser<'static> {
    ArgParser::new()
        .arg(
            Argument::new("input_file")
                .required(true)
                .takes_value(true)
                .help("File path of the JSON input."),
        )
        .arg(
            Argument::new("output_file")
                .required(false)
                .takes_value(true)
                .default_value("bpf.out")
                .help("Optional path of the output file."),
        )
        .arg(
            Argument::new("target_arch")
                .required(true)
                .takes_value(true)
                .help("ARCH of the CPU that will be used to run the BPF program. One of x86_64/aarch64"),
        )
}

fn get_argument_values(arguments: &ArgumentsBag) -> Result<Arguments> {
    let target_arch = arguments.value_as_string("target_arch").and_then(|val| {
        if !SUPPORTED_ARCHES.contains(&val.as_ref()) {
            None
        } else {
            Some(val)
        }
    });

    if target_arch.is_none() {
        return Err(Error::InvalidArch);
    }

    let input_file = arguments.value_as_string("input_file");
    if input_file.is_none() {
        return Err(Error::MissingInputFile);
    }

    Ok(Arguments {
        target_arch: target_arch.unwrap(),
        input_file: input_file.unwrap(),
        // Safe to unwrap because it has a default value
        output_file: arguments.value_as_string("output_file").unwrap(),
    })
}

fn parse_json(reader: &mut dyn Read) -> Result<HashMap<String, Filter>> {
    serde_json::from_reader(reader).map_err(Error::JSONError)
}

fn compile(args: &Arguments) -> Result<()> {
    let input_file = File::open(&args.input_file)
        .map_err(|err| Error::FileOpen(PathBuf::from(&args.input_file), err))?;
    let mut input_reader = BufReader::new(input_file);
    let filters = parse_json(&mut input_reader)?;
    let compiler = Compiler::new(&args.target_arch);

    // transform the IR into a Map of BPFPrograms
    let bpf_data: HashMap<String, BpfProgram> =
        compiler.compile_blob(filters).map_err(Error::FileFormat)?;

    // serialize the BPF programs & output them to a file
    let output_file = File::create(&args.output_file)
        .map_err(|err| Error::FileOpen(PathBuf::from(&args.output_file), err))?;
    bincode::serialize_into(output_file, &bpf_data).map_err(Error::Bincode)?;

    Ok(())
}

fn main() {
    let mut arg_parser = build_arg_parser();

    if let Err(err) = arg_parser.parse_from_cmdline() {
        println!(
            "Arguments parsing error: {} \n\n\
             For more information try --help.",
            err
        );
        process::exit(1);
    }

    if let Some(help) = arg_parser.arguments().value_as_bool("help") {
        if help {
            println!("Seccompiler v{}\n", SECCOMPILER_VERSION);
            println!("{}", arg_parser.formatted_help());
            process::exit(0);
        }
    }
    if let Some(version) = arg_parser.arguments().value_as_bool("version") {
        if version {
            println!("Seccompiler v{}\n", SECCOMPILER_VERSION);
            process::exit(0);
        }
    }

    let args = get_argument_values(arg_parser.arguments()).unwrap_or_else(|err| {
        println!(
            "{} \n\n\
            For more information try --help.",
            err
        );
        process::exit(1);
    });

    compile(&args).unwrap_or_else(|err| panic!("Seccompiler error: {}", err));

    println!("Filter successfully compiled into: {}", args.output_file);
}

#[cfg(test)]
mod tests {
    use super::compiler::{Error as FilterFormatError, Filter, SyscallObject};
    use super::{build_arg_parser, get_argument_values, parse_json, Arguments, Error};
    use bincode::Error as BincodeError;
    use seccomp::{SeccompAction, SeccompCmpArgLen::*, SeccompCmpOp::*, SeccompCondition as Cond};
    use std::collections::HashMap;
    use std::io;
    use std::path::PathBuf;

    #[test]
    fn test_error_messages() {
        let path = PathBuf::from("/path");
        assert_eq!(
            format!(
                "{}",
                Error::Bincode(BincodeError::new(bincode::ErrorKind::SizeLimit))
            ),
            format!(
                "Bincode (de)serialization failed: {}",
                BincodeError::new(bincode::ErrorKind::SizeLimit)
            )
        );
        assert_eq!(
            format!(
                "{}",
                Error::FileFormat(FilterFormatError::MultipleSyscallFields)
            ),
            format!("{}", FilterFormatError::MultipleSyscallFields)
        );
        assert_eq!(
            format!(
                "{}",
                Error::FileOpen(path.clone(), io::Error::from_raw_os_error(2))
            ),
            format!(
                "Failed to open file {:?}: {}",
                path,
                io::Error::from_raw_os_error(2)
            )
            .replace("\"", "")
        );
        assert_eq!(format!("{}", Error::InvalidArch), "Invalid arch");
        assert_eq!(format!("{}", Error::MissingInputFile), "Missing input file");
    }
    #[test]
    fn test_get_argument_values() {
        let arg_parser = build_arg_parser();
        let default_out_file_name = "bpf.out";
        // correct arguments
        let arguments = &mut arg_parser.arguments().clone();
        arguments
            .parse(
                vec![
                    "seccompiler",
                    "--input_file",
                    "foo.txt",
                    "--target_arch",
                    "x86_64",
                ]
                .into_iter()
                .map(String::from)
                .collect::<Vec<String>>()
                .as_ref(),
            )
            .unwrap();
        assert_eq!(
            get_argument_values(arguments).unwrap(),
            Arguments {
                input_file: "foo.txt".to_string(),
                output_file: default_out_file_name.to_string(),
                target_arch: "x86_64".to_string()
            }
        );

        let arguments = &mut arg_parser.arguments().clone();
        arguments
            .parse(
                vec![
                    "seccompiler",
                    "--input_file",
                    "foo.txt",
                    "--target_arch",
                    "x86_64",
                    "--output_file",
                    "/path.to/file.txt",
                ]
                .into_iter()
                .map(String::from)
                .collect::<Vec<String>>()
                .as_ref(),
            )
            .unwrap();
        assert_eq!(
            get_argument_values(arguments).unwrap(),
            Arguments {
                input_file: "foo.txt".to_string(),
                output_file: "/path.to/file.txt".to_string(),
                target_arch: "x86_64".to_string()
            }
        );

        // no args
        let arguments = &mut arg_parser.arguments().clone();
        assert!(arguments
            .parse(
                vec!["seccompiler"]
                    .into_iter()
                    .map(String::from)
                    .collect::<Vec<String>>()
                    .as_ref(),
            )
            .is_err());

        // invalid --target_arch
        let arguments = &mut arg_parser.arguments().clone();
        arguments
            .parse(
                vec![
                    "seccompiler",
                    "--input_file",
                    "foo.txt",
                    "--target_arch",
                    "x86_64das",
                    "--output_file",
                    "/path.to/file.txt",
                ]
                .into_iter()
                .map(String::from)
                .collect::<Vec<String>>()
                .as_ref(),
            )
            .unwrap();
        assert!(get_argument_values(arguments).is_err());
        // invalid --target_arch
        let arguments = &mut arg_parser.arguments().clone();
        arguments
            .parse(
                vec![
                    "seccompiler",
                    "--input_file",
                    "foo.txt",
                    "--target_arch",
                    "x86_64das",
                    "--output_file",
                    "/path.to/file.txt",
                ]
                .into_iter()
                .map(String::from)
                .collect::<Vec<String>>()
                .as_ref(),
            )
            .unwrap();
        assert!(get_argument_values(arguments).is_err());
    }

    #[allow(clippy::useless_asref)]
    #[test]
    fn test_parse_json() {
        // test with correctly formed JSON
        let mut json_input = r#"
        {
            "thread_1": {
                "default_action": {
                    "Errno": 12
                },
                "filter_action": "Allow",
                "filter": [
                    {
                        "syscall": "SYS_open",
                        "action": "Log"
                    },
                    {
                        "syscalls": [
                            "SYS_close",
                            "SYS_stat"
                        ],
                        "action": "Trap"
                    },
                    {
                        "syscall": "SYS_futex",
                        "args": [
                            {
                                "arg_index": 2,
                                "arg_type": "DWORD",
                                "op": "Le",
                                "val": 65
                            },
                            {
                                "arg_index": 1,
                                "arg_type": "QWORD",
                                "op": "Ne",
                                "val": 80
                            }
                        ]
                    },
                    {
                        "syscall": "SYS_futex",
                        "action": "Log",
                        "args": [
                            {
                                "arg_index": 3,
                                "arg_type": "QWORD",
                                "op": "Gt",
                                "val": 65
                            },
                            {
                                "arg_index": 1,
                                "arg_type": "QWORD",
                                "op": "Lt",
                                "val": 80
                            }
                        ]
                    },
                    {
                        "syscall": "SYS_futex",
                        "args": [
                            {
                                "arg_index": 3,
                                "arg_type": "QWORD",
                                "op": "Ge",
                                "val": 65
                            }
                        ]
                    },
                    {
                        "syscall": "SYS_ioctl",
                        "args": [
                            {
                                "arg_index": 3,
                                "arg_type": "DWORD",
                                "op": {
                                    "MaskedEq": 100
                                },
                                "val": 65
                            }
                        ]
                    }
                ]
            },
            "thread_2": {
                "default_action": "Trap",
                "filter_action": "Allow",
                "filter": [
                    {
                        "syscall": "SYS_ioctl",
                        "args": [
                            {
                                "arg_index": 3,
                                "arg_type": "DWORD",
                                "op": "Eq",
                                "val": 65
                            }
                        ]
                    }
                ]
            }
        }
        "#
        .to_string();
        let json_input = unsafe { json_input.as_bytes_mut() };

        let mut filters = HashMap::new();
        filters.insert(
            "thread_1".to_string(),
            Filter::new(
                SeccompAction::Errno(12),
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
                        None,
                        Some(vec![
                            Cond::new(2, DWORD, Le, 65).unwrap(),
                            Cond::new(1, QWORD, Ne, 80).unwrap(),
                        ]),
                    ),
                    SyscallObject::new(
                        Some("SYS_futex".to_string()),
                        None,
                        Some(SeccompAction::Log),
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
            ),
        );

        filters.insert(
            "thread_2".to_string(),
            Filter::new(
                SeccompAction::Trap,
                SeccompAction::Allow,
                vec![SyscallObject::new(
                    Some("SYS_ioctl".to_string()),
                    None,
                    None,
                    Some(vec![Cond::new(3, DWORD, Eq, 65).unwrap()]),
                )],
            ),
        );

        let mut v1: Vec<_> = filters.into_iter().collect();
        v1.sort_by(|x, y| x.0.cmp(&y.0));

        let mut v2: Vec<_> = parse_json(&mut json_input.as_ref())
            .unwrap()
            .into_iter()
            .collect();
        v2.sort_by(|x, y| x.0.cmp(&y.0));
        // assert_eq!(filters, parse_json(&mut json_input.as_ref()).unwrap());
        assert_eq!(v1, v2);
    }
}
