use eyre::{Result, bail};
use futures::{Stream, StreamExt, stream};
use log::warn;
use netlink_packet_core::{
    NetlinkDeserializable, NetlinkMessage, NetlinkPayload, NetlinkSerializable,
};
use netlink_proto::{ConnectionHandle, Error, new_connection, sys::AsyncSocket, sys::SocketAddr};
use nix::sys::socket::{getsockopt, sockopt};
use std::fmt::Debug;
use std::io;

pub mod netfilter;
pub mod wireguard;

/// Safety margin subtracted from `sk_sndbuf`: the kernel's own accounting
/// (`sk_sndbuf - 32` in `netlink_sendmsg`) plus a small headroom.
const SNDBUF_MARGIN: usize = 32 + 1024;

/// Upper bound on the derived batch size, so a host with a huge `SO_SNDBUF`
/// does not create datagrams larger than necessary (they must be copied through
/// the socket anyway).
const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;

/// Conservative fallback when `SO_SNDBUF` cannot be read.
const FALLBACK_BATCH_BYTES: usize = 132 * 1024;

/// The datagram cap derived from the socket's real send buffer, with the
/// kernel's own accounting and a small headroom subtracted, bounded above.
fn batch_bytes_for(sndbuf: usize) -> usize {
    sndbuf.saturating_sub(SNDBUF_MARGIN).min(MAX_BATCH_BYTES)
}

/// Iterator splitting messages into datagrams bounded by their cumulative
/// serialized size.
///
/// A message is never split, and every batch contains at least one message
/// (even if that single message exceeds `max_bytes`).
struct Batches<T, I> {
    msgs: I,
    max_bytes: usize,
    /// message that did not fit in the previous batch
    pending: Option<NetlinkMessage<T>>,
}

impl<T, I> Iterator for Batches<T, I>
where
    T: NetlinkSerializable,
    I: Iterator<Item = NetlinkMessage<T>>,
{
    type Item = Vec<NetlinkMessage<T>>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut batch = Vec::new();
        let mut bytes = 0;

        // resume with the message that overflowed the previous batch
        if let Some(msg) = self.pending.take() {
            bytes = msg.buffer_len();
            batch.push(msg);
        }

        for msg in self.msgs.by_ref() {
            let len = msg.buffer_len();

            // a batch always holds at least one message, even oversized
            if !batch.is_empty() && bytes + len > self.max_bytes {
                self.pending = Some(msg);
                break;
            }

            bytes += len;
            batch.push(msg);
        }

        (!batch.is_empty()).then_some(batch)
    }
}

/// Split messages into datagrams bounded by their cumulative serialized size.
fn batches<T: NetlinkSerializable>(
    msgs: impl IntoIterator<Item = NetlinkMessage<T>>,
    max_bytes: usize,
) -> Batches<T, impl Iterator<Item = NetlinkMessage<T>>> {
    Batches {
        msgs: msgs.into_iter(),
        max_bytes,
        pending: None,
    }
}

/// A netlink connection together with the derived maximum datagram size.
///
/// The connection runs on a spawned task; this type only keeps the handle and
/// the destination. The maximum datagram size is read from the socket's real
/// `SO_SNDBUF` at creation, since `netlink_sendmsg` rejects any datagram larger
/// than `sk_sndbuf - 32` with `EMSGSIZE` (fatal to the whole connection).
pub struct Netlink<T: Debug> {
    handle: ConnectionHandle<T>,
    dest: SocketAddr,
    max_batch_bytes: usize,
}

impl<T> Netlink<T>
where
    T: Debug + NetlinkSerializable + NetlinkDeserializable + Unpin + Send + 'static,
{
    /// Open a netlink connection for `protocol` and spawn its task.
    pub fn new(protocol: isize) -> io::Result<Self> {
        let (mut conn, handle, _) = new_connection::<T>(protocol)?;

        // read the real send buffer before handing the connection to the task
        let max_batch_bytes = match getsockopt(conn.socket_mut().socket_ref(), sockopt::SndBuf) {
            Ok(sndbuf) => {
                let cap = batch_bytes_for(sndbuf);
                log::debug!("netlink SO_SNDBUF is {sndbuf}, batching up to {cap} bytes");
                cap
            }
            Err(e) => {
                warn!("failed to read SO_SNDBUF, using {FALLBACK_BATCH_BYTES} bytes: {e}");
                FALLBACK_BATCH_BYTES
            }
        };

        tokio::spawn(conn);

        Ok(Self {
            handle,
            dest: SocketAddr::new(0, 0),
            max_batch_bytes,
        })
    }

    pub fn handle(&self) -> &ConnectionHandle<T> {
        &self.handle
    }

    /// The destination (the kernel) for requests.
    pub fn dest(&self) -> SocketAddr {
        self.dest
    }

    /// The largest cumulative serialized size accepted in a single datagram.
    pub fn max_batch_bytes(&self) -> usize {
        self.max_batch_bytes
    }

    /// Send messages in as few datagrams as possible, yielding every response.
    ///
    /// The returned stream yields the responses of every message across every
    /// datagram, as well as any send error (so a failure of one datagram does
    /// not abort the remaining ones).
    ///
    /// Caller MUST consume ALL responses to drain the socket.
    pub fn send_batched<'a>(
        &'a self,
        msgs: impl IntoIterator<Item = NetlinkMessage<T>> + 'a,
    ) -> impl Stream<Item = Result<NetlinkMessage<T>, Error<T>>> + 'a
    where
        T: Debug + NetlinkSerializable + Send,
    {
        let handle = &self.handle;
        let dest = self.dest;
        stream::iter(batches(msgs, self.max_batch_bytes)).flat_map(move |batch| {
            match handle.request_batch(batch, dest) {
                Ok(responses) => responses.map(Ok).boxed(),
                Err(e) => stream::once(async move { Err(e) }).boxed(),
            }
        })
    }

    /// Send whole transactions (each one single datagram), yielding the first
    /// error.
    ///
    /// A transaction is a `Vec` of messages delivered in a single datagram:
    /// netlink rejects a datagram larger than `sk_sndbuf - 32`, and nfnetlink
    /// processes a batch (begin..end) from that single datagram, so
    /// transactions cannot span datagrams. Callers must therefore keep each
    /// transaction under [`Netlink::max_batch_bytes`].
    ///
    /// Unlike [`Netlink::send_batched`], only the first error is reported and
    /// the remaining transactions are sent regardless.
    pub async fn send_transactions(
        &self,
        txs: impl IntoIterator<Item = Vec<NetlinkMessage<T>>>,
    ) -> Result<()>
    where
        T: Debug + NetlinkSerializable + Send,
    {
        for tx in txs {
            if tx.is_empty() {
                continue;
            }

            let mut responses = match self.handle.request_batch(tx, self.dest) {
                Ok(responses) => responses,
                // `Error<T>` is only Debug when `T` is, which is not guaranteed here
                Err(_) => bail!("failed to send netlink transaction"),
            };
            while let Some(message) = responses.next().await {
                if let NetlinkPayload::Error(err) = message.payload
                    && err.code.is_some()
                {
                    bail!("netlink error: {err:?}");
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::{NetlinkHeader, NetlinkPayload};

    /// Fake message with a fixed serialized size, for exercising `batches`.
    struct Fake {
        len: usize,
    }

    impl Fake {
        fn new(len: usize) -> NetlinkMessage<Self> {
            NetlinkMessage::new(
                NetlinkHeader::default(),
                NetlinkPayload::InnerMessage(Self { len }),
            )
        }
    }

    impl NetlinkSerializable for Fake {
        fn message_type(&self) -> u16 {
            0
        }
        fn buffer_len(&self) -> usize {
            self.len
        }
        fn serialize(&self, _buffer: &mut [u8]) {}
    }

    impl Debug for Fake {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Fake({})", self.len)
        }
    }

    /// total serialized size of a fake message (includes the netlink header)
    fn total(msg: &NetlinkMessage<Fake>) -> usize {
        msg.buffer_len()
    }

    fn batch_sizes(batch: &[NetlinkMessage<Fake>]) -> Vec<usize> {
        batch.iter().map(total).collect()
    }

    #[test]
    fn empty() {
        assert!(batches::<Fake>([], 100).next().is_none());
    }

    #[test]
    fn exact_fit() {
        let unit = total(&Fake::new(0));
        let msgs = (0..3).map(|_| Fake::new(0)).collect::<Vec<_>>();
        let out = batches(msgs, unit * 3).collect::<Vec<_>>();
        assert_eq!(out.len(), 1);
        assert_eq!(batch_sizes(&out[0]), [unit; 3]);
    }

    #[test]
    fn one_over_splits() {
        let unit = total(&Fake::new(0));
        let msgs = (0..3).map(|_| Fake::new(0)).collect::<Vec<_>>();
        let out = batches(msgs, unit * 3 - 1).collect::<Vec<_>>();
        assert_eq!(out.len(), 2);
        assert_eq!(batch_sizes(&out[0]), [unit; 2]);
        assert_eq!(batch_sizes(&out[1]), [unit]);
    }

    #[test]
    fn oversized_alone() {
        let small = total(&Fake::new(0));
        let big = total(&Fake::new(small * 4));
        let msgs = vec![Fake::new(small * 4), Fake::new(0)];
        let out = batches(msgs, small).collect::<Vec<_>>();
        assert_eq!(out.len(), 2);
        assert_eq!(batch_sizes(&out[0]), [big]);
        assert_eq!(batch_sizes(&out[1]), [small]);
    }

    #[test]
    fn sndbuf_cap_derivation() {
        // a typical default: 208 KiB -> margin applied
        assert_eq!(batch_bytes_for(212_992), 212_992 - (32 + 1024));
        // never above the ceiling
        assert_eq!(batch_bytes_for(64 * 1024 * 1024), MAX_BATCH_BYTES);
        // saturates at zero for tiny values
        assert_eq!(batch_bytes_for(16), 0);
    }
}
