pub mod chain;
pub mod rules;
pub mod set;
pub mod table;
pub mod table_sync;
pub mod userdata;

use eyre::Result;
use log::debug;
use netlink_packet_core::NetlinkMessage;
use netlink_packet_netfilter::{NetfilterHeader, NetfilterMessage, NetfilterProtoFamily};
use std::{io::Cursor, process::Stdio};
use tokio::{io, io::AsyncRead, process::Command};

pub type Message = NetlinkMessage<NetfilterMessage>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("io error: {0}")]
    Io(std::io::Error),
    #[error("exit code {0}")]
    Exit(i32),
}

pub async fn apply_script(script: impl Into<String>) -> Result<(), Error> {
    let script = script.into();
    debug!("nft script:\n{script}");

    apply_from_reader(Cursor::new(script)).await
}

pub async fn apply_from_reader<R>(mut script: R) -> Result<(), Error>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let mut cmd = Command::new("nft");
    cmd.args(["-f", "-"]);
    cmd.stdin(Stdio::piped());

    let mut child = cmd.spawn().map_err(Error::Io)?;

    let mut nft_in = child.stdin.take().expect("stdin should exist");
    tokio::spawn(async move { io::copy(&mut script, &mut nft_in).await });

    let s = child.wait().await.map_err(Error::Io)?;
    if !s.success() {
        return Err(Error::Exit(s.code().unwrap_or(0)));
    }

    Ok(())
}

fn nft_header() -> NetfilterHeader {
    NetfilterHeader::new(NetfilterProtoFamily::Inet, 0, 0)
}

/// Test helpers shared by the nftables subsystems.
///
/// A golden scenario is a list of [`Op`]s run against a [`System`]: at every
/// `Verify`, the rendered table is applied to the real kernel and its
/// `nft list` output (minus the `table <name> { … }` wrapper) is compared.
#[cfg(test)]
pub mod test_harness;
