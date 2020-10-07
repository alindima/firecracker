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
use std::io::BufReader;
use std::path::PathBuf;
use std::process;
use std::result::Result;
use utils::arg_parser::{ArgParser, Argument};

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

struct Arguments {
    input_file: String,
    output_file: String,
    target_arch: String,
}

pub fn build_arg_parser() -> ArgParser<'static> {
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

fn get_argument_values(arg_parser: &ArgParser) -> Result<Arguments, Error> {
    let target_arch = arg_parser
        .arguments()
        .value_as_string("target_arch")
        .and_then(|val| {
            if !SUPPORTED_ARCHES.contains(&val.as_ref()) {
                None
            } else {
                Some(val)
            }
        });

    if target_arch.is_none() {
        return Err(Error::InvalidArch);
    }

    let input_file = arg_parser.arguments().value_as_string("input_file");
    if input_file.is_none() {
        return Err(Error::MissingInputFile);
    }

    Ok(Arguments {
        target_arch: target_arch.unwrap(),
        input_file: input_file.unwrap(),
        // Safe to unwrap because it has a default value
        output_file: arg_parser
            .arguments()
            .value_as_string("output_file")
            .unwrap(),
    })
}

fn parse_json_file(path: &str) -> Result<HashMap<String, Filter>, Error> {
    let input_file = File::open(path).map_err(|err| Error::FileOpen(PathBuf::from(path), err))?;
    let input_reader = BufReader::new(input_file);
    serde_json::from_reader(input_reader).map_err(Error::JSONError)
}

fn compile(args: &Arguments) -> Result<(), Error> {
    let filters = parse_json_file(&args.input_file)?;
    let compiler = Compiler::new(&args.target_arch);

    compiler
        .validate_filters(&filters)
        .map_err(Error::FileFormat)?;

    // transform the IR into a Map of BPFPrograms
    let bpf_data: HashMap<String, BpfProgram> =
        compiler.compile_blob(filters).map_err(Error::FileFormat)?;

    // serialize the BPF programs & output them to a file
    let output_file = File::create(&args.output_file)
        .map_err(|err| Error::FileOpen(PathBuf::from(&args.output_file), err))?;
    bincode::serialize_into(output_file, &bpf_data).map_err(Error::Bincode)?;
    // println!("{:#?}", bpf_data);

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

    let args = get_argument_values(&arg_parser).unwrap_or_else(|err| {
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
mod tests {}
