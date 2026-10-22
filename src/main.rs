use std::process::ExitCode;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use netscope::cli::Args;

fn main() -> ExitCode {
    let args = Args::parse();
    let level = match args.verbose {
        0 => "netscope=info",
        1 => "netscope=debug",
        _ => "netscope=trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level)))
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    match netscope::app::run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            pause_if_own_console();
            ExitCode::FAILURE
        }
    }
}

/// Started by a double click, the console window closes with the process and the error
/// would never be read: wait for Enter when this process is the only one on the console.
fn pause_if_own_console() {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Console::GetConsoleProcessList;
        let mut pids = [0u32; 2];
        // SAFETY: the buffer and its length are passed together; the call only writes into it.
        let n = unsafe { GetConsoleProcessList(pids.as_mut_ptr(), pids.len() as u32) };
        if n == 1 {
            eprintln!("\nPress Enter to close this window...");
            let _ = std::io::stdin().read_line(&mut String::new());
        }
    }
}
