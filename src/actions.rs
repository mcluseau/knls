use log::info;
use tokio::process::Command;

use crate::nftables;

pub async fn run_event(target: &str, event: &str, actions: &[Action]) -> eyre::Result<()> {
    if actions.is_empty() {
        info!(target: target, "no {event} actions");
        return Ok(());
    }

    info!(target: target, "running {event} actions");
    run(actions)
        .await
        .map_err(|(n, e)| eyre::format_err!("{event} action[{n}] failed: {e}"))
}

pub async fn run(actions: &[Action]) -> std::result::Result<(), (usize, Error)> {
    for (n, action) in actions.iter().enumerate() {
        action.run().await.map_err(|e| (n, e))?;
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Actions(Vec<Action>),
    Exec {
        cmd: String,
        args: Vec<String>,
    },
    Nft(String),
    NftChain {
        table: String,
        chain: String,
        rules: String,
    },
}

impl Action {
    pub async fn run(&self) -> Result {
        use Action as A;
        match self {
            A::Actions(actions) => {
                for (n, action) in actions.iter().enumerate() {
                    (Box::pin(action.run()).await)
                        .map_err(|e| Error::NthActionFailed(n, Box::new(e)))?;
                }
            }
            A::Exec { cmd, args } => {
                let s = (Command::new(cmd).args(args).status().await).map_err(Error::ExecFailed)?;
                if !s.success() {
                    return Err(Error::ExecCommandFailed(s.code().unwrap_or(0)));
                }
            }
            A::Nft(script) => {
                nftables::apply_script(script)
                    .await
                    .map_err(Error::NftFailed)?;
            }
            A::NftChain {
                table,
                chain,
                rules,
            } => {
                let script = format!(
                    r#"
table inet {table} {{}};
chain inet {table} {chain} {{}};
delete chain inet {table} {chain};
table inet {table} {{
  chain {chain} {{
{rules}
  }}
}}
                "#
                );
                nftables::apply_script(script)
                    .await
                    .map_err(Error::NftFailed)?;
            }
        }
        Ok(())
    }
}

pub type Result = std::result::Result<(), Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}th failed: {1}")]
    NthActionFailed(usize, Box<Error>),
    #[error("exec failed: {0}")]
    ExecFailed(std::io::Error),
    #[error("exec: exit code {0}")]
    ExecCommandFailed(i32),
    #[error("nft failed: {0}")]
    NftFailed(nftables::Error),
}
