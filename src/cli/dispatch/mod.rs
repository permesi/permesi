use crate::cli::actions::Action;
use anyhow::Result;

pub fn handler(matches: &clap::ArgMatches) -> Result<Action> {
    // Closure to return subcommand matches
    // let sub_m = |subcommand| -> Result<&clap::ArgMatches> {
    //     matches
    //         .subcommand_matches(subcommand)
    //         .context("arguments not found")
    // };
    //
    // match matches.subcommand_name() {
    Ok(Action::Server {
        port: matches.get_one::<u16>("port").copied().unwrap_or(8080),
        dsn: matches
            .get_one("dsn")
            .map(|s: &String| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("missing required argument: --dsn"))?,
    })
}
