use canton_solvency_verify::args::{parse, Command, USAGE};
use canton_solvency_verify::diff::run_diff;
use canton_solvency_verify::output::{
    render_diff_json, render_diff_text, render_json, render_text,
};
use canton_solvency_verify::{
    exit_code, run::run, EXIT_OK, EXIT_USAGE_OR_IO, EXIT_VERIFICATION_FAILED,
};

fn main() {
    let command = match parse(std::env::args().skip(1)) {
        Ok(command) => command,
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(EXIT_USAGE_OR_IO);
        }
    };

    match command {
        Command::Help => {
            println!("{USAGE}");
            std::process::exit(EXIT_OK);
        }
        Command::Version => {
            println!("canton-solvency-verify {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(EXIT_OK);
        }
        _ => {}
    }

    if let Command::ManifestDiff { json, .. } = command {
        match run_diff(&command) {
            Ok(summary) => {
                print!(
                    "{}",
                    if json {
                        render_diff_json(&summary) + "\n"
                    } else {
                        render_diff_text(&summary)
                    }
                );
                std::process::exit(if summary.has_reductions() {
                    EXIT_VERIFICATION_FAILED
                } else {
                    EXIT_OK
                });
            }
            Err(e) => {
                eprintln!("error: {e:#}");
                std::process::exit(EXIT_USAGE_OR_IO);
            }
        }
    }

    let json = matches!(
        command,
        Command::Verify { json: true, .. }
            | Command::VerifyGroup { json: true, .. }
            | Command::VerifyChain { json: true, .. }
    );
    let result = run(&command);
    let code = exit_code(&result);

    match &result {
        Ok(summary) => print!(
            "{}",
            if json {
                render_json(summary) + "\n"
            } else {
                render_text(summary)
            }
        ),
        Err(e) => eprintln!("error: {e:#}"),
    }
    std::process::exit(code);
}
