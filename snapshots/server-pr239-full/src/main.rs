//! Thin binary entrypoint. All logic lives in the library modules
//! (`config`, `supabase`, `db`, `token`, `http`, …) so `main.rs` stays a
//! shell: initialise telemetry, dispatch the subcommand, surface the exit code.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    if shared_auth_server::run().await.is_err() {
        // The structured ORES security event was already emitted and flushed by
        // `run`. Never print an anyhow chain here: provider responses, URLs,
        // token fragments, or key paths can be embedded in error Display text.
        eprintln!("fatal: shared-auth-server failed; inspect structured logs");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
