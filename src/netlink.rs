use eyre::{Result, bail};
use futures::{Stream, StreamExt, stream};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NetlinkSerializable};
use netlink_proto::{ConnectionHandle, Error, sys::SocketAddr};
use std::fmt::Debug;

/// Maximum cumulative serialized size of the messages sent in a single datagram.
///
/// `netlink_sendmsg` rejects a datagram larger than `sk_sndbuf - 32` with
/// `EMSGSIZE`, and that error is fatal to the whole netlink connection (the
/// spawned `Connection` shuts down). `sk_sndbuf` defaults to
/// `net.core.wmem_default` (~208 KiB), so 128 KiB keeps a wide margin. A single
/// message always fits: ours are bounded well below that (the largest, an nft
/// set element, is capped by the 16-bit `nlattr.nla_len`).
pub(crate) const BATCH_BYTES: usize = 128 * 1024;

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

/// Send messages in as few datagrams as possible, yielding every response.
///
/// The returned stream yields the responses of every message across every
/// datagram, as well as any send error (so a failure of one datagram does not
/// abort the remaining ones).
///
/// Caller MUST consume ALL responses to drain the socket.
pub fn send_batched<'a, T>(
    handle: &'a ConnectionHandle<T>,
    dest: SocketAddr,
    msgs: impl IntoIterator<Item = NetlinkMessage<T>> + 'a,
) -> impl Stream<Item = Result<NetlinkMessage<T>, Error<T>>> + 'a
where
    T: Debug + NetlinkSerializable + Send,
{
    stream::iter(batches(msgs, BATCH_BYTES)).flat_map(move |batch| {
        match handle.request_batch(batch, dest) {
            Ok(responses) => responses.map(Ok).boxed(),
            Err(e) => stream::once(async move { Err(e) }).boxed(),
        }
    })
}

/// Send whole transactions (each one single datagram), yielding the first error.
///
/// A transaction is a `Vec` of messages delivered in a single datagram: netlink
/// rejects a datagram larger than `sk_sndbuf - 32`, and nfnetlink processes a
/// batch (begin..end) from that single datagram, so transactions cannot span
/// datagrams. Callers must therefore keep each transaction under
/// [`BATCH_BYTES`].
///
/// Unlike [`send_batched`], only the first error is reported and the remaining
/// transactions are sent regardless.
pub async fn send_transactions<T>(
    handle: &ConnectionHandle<T>,
    dest: SocketAddr,
    txs: impl IntoIterator<Item = Vec<NetlinkMessage<T>>>,
) -> Result<()>
where
    T: Debug + NetlinkSerializable + Send,
{
    for tx in txs {
        if tx.is_empty() {
            continue;
        }

        let mut responses = match handle.request_batch(tx, dest) {
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
}
