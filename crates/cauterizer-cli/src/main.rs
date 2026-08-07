//! Cauterizer local operator CLI.

#![forbid(unsafe_code)]

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match cauterizer_cli::parse_args(&arguments) {
        Ok(command) => println!("{command:?}"),
        Err(_) => eprintln!(
            "usage: cauterizer remediation <trigger|status|cancel|reconcile> ... ({})",
            cauterizer_contracts::SCHEMA_NAMESPACE
        ),
    }
}
