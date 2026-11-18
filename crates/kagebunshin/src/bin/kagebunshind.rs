use std::process::ExitCode;

#[expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "the entry point: --version, usage and the fatal error"
)]
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => {}
        ["--version" | "-V"] => {
            println!("kagebunshind {}", kagebunshin::ipc::protocol::BUILD_ID);
            return ExitCode::SUCCESS;
        }
        _ => {
            eprintln!("usage: kagebunshind [--version]");
            return ExitCode::from(2);
        }
    }
    match kagebunshin::daemon::run(kagebunshin::daemon::Options::default()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kagebunshind: {e}");
            ExitCode::FAILURE
        }
    }
}
