use canton_solvency_verify::anchors::run_anchors;
use canton_solvency_verify::args::{parse, Command, USAGE};
use canton_solvency_verify::assurance::run_assurance;
use canton_solvency_verify::coverage::run_coverage;
use canton_solvency_verify::diff::run_diff;
use canton_solvency_verify::output::{
    render_assurance_json, render_assurance_text, render_chain_json, render_chain_text,
    render_coverage_json, render_coverage_text, render_diff_json, render_diff_text, render_json,
    render_pack_json, render_pack_text, render_recompute_json, render_recompute_text, render_text,
};
use canton_solvency_verify::pack::run_pack;
use canton_solvency_verify::provenance::{
    render_provenance_json, render_provenance_text, run_provenance,
};
use canton_solvency_verify::recompute::run_recompute;
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

    if let Command::Provenance { json, .. } = command {
        match run_provenance(&command) {
            Ok(outcome) => {
                print!(
                    "{}",
                    if json {
                        render_provenance_json(&outcome) + "\n"
                    } else {
                        render_provenance_text(&outcome)
                    }
                );
                std::process::exit(if outcome.ok() {
                    EXIT_OK
                } else {
                    EXIT_VERIFICATION_FAILED
                });
            }
            Err(e) => {
                eprintln!("error: {e:#}");
                std::process::exit(EXIT_USAGE_OR_IO);
            }
        }
    }

    if let Command::Assurance { json, .. } = command {
        match run_assurance(&command) {
            Ok(outcome) => {
                print!(
                    "{}",
                    if json {
                        render_assurance_json(&outcome) + "\n"
                    } else {
                        render_assurance_text(&outcome)
                    }
                );
                std::process::exit(if outcome.ok() {
                    EXIT_OK
                } else {
                    EXIT_VERIFICATION_FAILED
                });
            }
            Err(e) => {
                eprintln!("error: {e:#}");
                std::process::exit(EXIT_USAGE_OR_IO);
            }
        }
    }

    if let Command::Recompute { json, .. } = command {
        match run_recompute(&command) {
            Ok(outcome) => {
                print!(
                    "{}",
                    if json {
                        render_recompute_json(&outcome) + "\n"
                    } else {
                        render_recompute_text(&outcome)
                    }
                );
                std::process::exit(if outcome.matches() {
                    EXIT_OK
                } else {
                    EXIT_VERIFICATION_FAILED
                });
            }
            Err(e) => {
                eprintln!("error: {e:#}");
                std::process::exit(EXIT_USAGE_OR_IO);
            }
        }
    }

    if let Command::VerifyPack { json, .. } = command {
        match run_pack(&command) {
            Ok(summary) => {
                print!(
                    "{}",
                    if json {
                        render_pack_json(&summary) + "\n"
                    } else {
                        render_pack_text(&summary)
                    }
                );
                std::process::exit(if summary.all_passed() {
                    EXIT_OK
                } else {
                    EXIT_VERIFICATION_FAILED
                });
            }
            Err(e) => {
                eprintln!("error: {e:#}");
                std::process::exit(EXIT_USAGE_OR_IO);
            }
        }
    }

    if let Command::Anchors { json, .. } = command {
        match run_anchors(&command) {
            Ok(summary) => {
                print!(
                    "{}",
                    if json {
                        render_chain_json(&summary) + "\n"
                    } else {
                        render_chain_text(&summary)
                    }
                );
                std::process::exit(if summary.intact() {
                    EXIT_OK
                } else {
                    EXIT_VERIFICATION_FAILED
                });
            }
            Err(e) => {
                eprintln!("error: {e:#}");
                std::process::exit(EXIT_USAGE_OR_IO);
            }
        }
    }

    if let Command::Coverage { json, .. } = command {
        match run_coverage(&command) {
            Ok(outcome) => {
                print!(
                    "{}",
                    if json {
                        render_coverage_json(&outcome) + "\n"
                    } else {
                        render_coverage_text(&outcome)
                    }
                );
                std::process::exit(if outcome.ok() {
                    EXIT_OK
                } else {
                    EXIT_VERIFICATION_FAILED
                });
            }
            Err(e) => {
                eprintln!("error: {e:#}");
                std::process::exit(EXIT_USAGE_OR_IO);
            }
        }
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
