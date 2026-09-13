//! Apps, orgs, versions, share grants.
//! `runtime: Wasm | MicroVM` is stored as a single field here and never
//! branched on above clwd-runtime.
//!
//! # `bootstrap-token`
//!
//! ```text
//! control-plane bootstrap-token --org <slug> --name <name> --scopes admin \
//!     --direct-database-write
//! ```
//!
//! Until OIDC lands (#9) nothing can call the issuance route without a token,
//! so the first one is written straight into the database. This grants nothing
//! new — whoever holds `DATABASE_URL` already has full control — but it is an
//! operator's tool, and it refuses to run without a flag that says what it
//! does, so nobody reaches it by accident.
//!
//! The token goes to stdout and nothing else does, so `$(...)` captures exactly
//! the token. It is shown once.

use anyhow::{Context as _, bail, ensure};
use control_plane::{auth, db, token::Scopes};

const SUBCOMMAND: &str = "bootstrap-token";
const CONFIRM: &str = "--direct-database-write";
const USAGE: &str = "usage: control-plane bootstrap-token --org <slug> --name <name> \
                     --scopes <scope,...> --direct-database-write";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    shared::telemetry::init();

    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some(SUBCOMMAND) {
        return bootstrap(parse(args)?).await;
    }

    tracing::info!("control-plane starting");
    Ok(())
}

#[derive(Debug)]
struct Bootstrap {
    org: String,
    name: String,
    scopes: Scopes,
}

fn parse(mut args: impl Iterator<Item = String>) -> anyhow::Result<Bootstrap> {
    let (mut org, mut name, mut scopes, mut confirmed) = (None, None, None, false);

    while let Some(flag) = args.next() {
        let mut value = || {
            args.next()
                .with_context(|| format!("{flag} needs a value\n{USAGE}"))
        };
        match flag.as_str() {
            "--org" => org = Some(value()?),
            "--name" => name = Some(value()?),
            "--scopes" => scopes = Some(Scopes::parse_all(value()?.split(','))?),
            CONFIRM => confirmed = true,
            _ => bail!("unexpected argument {flag:?}\n{USAGE}"),
        }
    }

    ensure!(
        confirmed,
        "refusing to run without {CONFIRM}: this writes a credential straight into the \
         database, bypassing the API\n{USAGE}"
    );

    Ok(Bootstrap {
        org: org.with_context(|| format!("--org is required\n{USAGE}"))?,
        name: name.with_context(|| format!("--name is required\n{USAGE}"))?,
        scopes: scopes.with_context(|| format!("--scopes is required\n{USAGE}"))?,
    })
}

async fn bootstrap(args: Bootstrap) -> anyhow::Result<()> {
    let url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL must name the control plane's database")?;
    let pool = sqlx::PgPool::connect(&url)
        .await
        .context("connecting to the database")?;

    let org = db::org_by_slug(&pool, &args.org)
        .await?
        .with_context(|| format!("no live org has the slug {:?}", args.org))?;
    let issued = auth::issue(&pool, org.id, None, &args.name, args.scopes).await?;

    eprintln!(
        "issued token {} for org {} with scopes: {}. It is shown once and cannot be recovered.",
        issued.id, org.slug, args.scopes
    );
    println!("{}", issued.secret.expose());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> impl Iterator<Item = String> {
        list.iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn a_complete_invocation_parses() {
        let parsed = parse(args(&[
            "--org",
            "acme",
            "--name",
            "ci",
            "--scopes",
            "admin,publish",
            CONFIRM,
        ]))
        .expect("complete");
        assert_eq!(parsed.org, "acme");
        assert_eq!(parsed.name, "ci");
        assert_eq!(parsed.scopes.to_names(), ["publish", "admin"]);
    }

    /// The flag is the guard against running this by accident.
    #[test]
    fn it_refuses_without_the_confirmation_flag() {
        let err = parse(args(&[
            "--org", "acme", "--name", "ci", "--scopes", "admin",
        ]))
        .expect_err("unconfirmed");
        assert!(err.to_string().contains(CONFIRM), "{err}");
    }

    #[test]
    fn unknown_arguments_and_scopes_are_rejected() {
        assert!(parse(args(&["--org", "acme", "--verbose", CONFIRM])).is_err());
        assert!(parse(args(&["--scopes", "root", CONFIRM])).is_err());
        assert!(parse(args(&["--org"])).is_err(), "a flag with no value");
    }
}
