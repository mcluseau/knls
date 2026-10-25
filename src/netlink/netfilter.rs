use super::{MAX_TX_MESSAGES, Netlink};
use eyre::Result;
use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage};
use netlink_packet_netfilter::{
    NetfilterHeader, NetfilterMessage, NetfilterProtoFamily, NetfilterSubsystem,
    none::ControlMessage,
};
use netlink_proto::sys::protocols::NETLINK_NETFILTER;
use std::{future::Future, io, iter::Once, slice};

pub type Message = NetlinkMessage<NetfilterMessage>;

/// One aggregation unit for [`NetlinkExt::send_groups`].
///
/// A [`Single`](Self::Single) message may share a transaction with its
/// neighbours. An [`Atomic`](Self::Atomic) group must be committed as a whole
/// (e.g. an anonymous set, its elements and the rule that binds it): the kernel
/// commits a transaction atomically, so separating them fails (`-EINVAL`,
/// "unbound set") and filling a set after it is bound fails (`-EBUSY`). An
/// atomic group is never split: when it does not fit in the current transaction
/// it starts a new one, even if that exceeds the caps on its own.
#[derive(Debug)]
pub enum Group {
    /// A single message, freely packable with other groups.
    Single(Message),
    /// Messages that must reach the kernel in the same transaction.
    Atomic(Vec<Message>),
}

impl Group {
    /// The number of messages in the group.
    pub fn len(&self) -> usize {
        match self {
            Self::Single(_) => 1,
            Self::Atomic(msgs) => msgs.len(),
        }
    }

    /// Whether the group is empty.
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Single(_) => false,
            Self::Atomic(msgs) => msgs.is_empty(),
        }
    }

    /// The group's serialized size, in bytes.
    pub fn bytes_len(&self) -> usize {
        match self {
            Self::Single(msg) => msg.buffer_len(),
            Self::Atomic(msgs) => msgs.iter().map(|msg| msg.buffer_len()).sum(),
        }
    }

    /// The group's messages.
    pub fn as_slice(&self) -> &[Message] {
        match self {
            Self::Single(msg) => slice::from_ref(msg),
            Self::Atomic(msgs) => msgs,
        }
    }
}

impl From<Message> for Group {
    fn from(msg: Message) -> Self {
        Self::Single(msg)
    }
}

/// Owning iterator over a [`Group`]'s messages.
pub enum GroupIntoIter {
    Single(Once<Message>),
    Atomic(std::vec::IntoIter<Message>),
}

impl Iterator for GroupIntoIter {
    type Item = Message;

    fn next(&mut self) -> Option<Message> {
        match self {
            Self::Single(msg) => msg.next(),
            Self::Atomic(msgs) => msgs.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Single(msg) => msg.size_hint(),
            Self::Atomic(msgs) => msgs.size_hint(),
        }
    }
}

impl ExactSizeIterator for GroupIntoIter {}

impl IntoIterator for Group {
    type Item = Message;
    type IntoIter = GroupIntoIter;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Self::Single(msg) => GroupIntoIter::Single(std::iter::once(msg)),
            Self::Atomic(msgs) => GroupIntoIter::Atomic(msgs.into_iter()),
        }
    }
}

pub fn new_link() -> io::Result<Netlink<NetfilterMessage>> {
    Netlink::<NetfilterMessage>::new(NETLINK_NETFILTER)
}

pub trait NetlinkExt {
    /// Send messages in transactions bounded by size and message count.
    fn send_as_transactions(
        &self,
        msgs: impl Iterator<Item = Message> + Send,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Send [`Group`]s in transactions bounded by size and message count,
    /// never splitting a group.
    fn send_groups(
        &self,
        groups: impl Iterator<Item = Group> + Send,
    ) -> impl Future<Output = Result<()>> + Send;
}

impl NetlinkExt for Netlink<NetfilterMessage> {
    async fn send_as_transactions(&self, msgs: impl Iterator<Item = Message> + Send) -> Result<()> {
        self.send_groups(msgs.map(Group::from)).await
    }

    async fn send_groups(&self, groups: impl Iterator<Item = Group> + Send) -> Result<()> {
        self.send_transactions(Transactions::new(
            groups,
            self.max_batch_bytes(),
            MAX_TX_MESSAGES,
        ))
        .await
    }
}

/// Iterator packing [`Group`]s into nfnetlink transactions, each of which is
/// sent as one datagram.
///
/// Transactions are bounded by their cumulative serialized size and their
/// message count; a group that would exceed either cap starts a new
/// transaction. A single group larger than the caps is still emitted as one
/// (oversized) transaction, since splitting it would break its atomicity.
struct Transactions<I> {
    groups: I,
    max_bytes: usize,
    max_messages: usize,
    /// group that did not fit in the previous transaction
    pending: Option<Group>,
}

impl<I> Transactions<I> {
    fn new(groups: I, max_bytes: usize, max_messages: usize) -> Self {
        // deduct tx overhead (batch begin/end messages) from max_bytes, so max_bytes is the actual
        // inner transaction max size.
        let max_bytes =
            max_bytes.saturating_sub(batch_begin().buffer_len() + batch_end().buffer_len());
        Self {
            groups,
            max_bytes,
            max_messages,
            pending: None,
        }
    }
}

impl<I: Iterator<Item = Group>> Iterator for Transactions<I> {
    type Item = Vec<Message>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut tx = vec![batch_begin()];
        let mut bytes = 0;
        let mut count = 0; // inner messages in `tx`

        loop {
            let group = match self.pending.take() {
                Some(group) => group,
                None => match self.groups.next() {
                    Some(group) => group,
                    None => break,
                },
            };
            if group.is_empty() {
                continue;
            }

            let len = group.len();
            let group_bytes = group.bytes_len();
            if count > 0
                && (count + len > self.max_messages || bytes + group_bytes > self.max_bytes)
            {
                self.pending = Some(group);
                break;
            }

            bytes += group_bytes;
            count += len;
            match group {
                Group::Single(msg) => tx.push(msg),
                Group::Atomic(msgs) => tx.extend(msgs),
            }
        }

        if count == 0 {
            return None;
        }
        tx.push(batch_end());
        Some(tx)
    }
}

fn batch_begin() -> Message {
    batch_msg(ControlMessage::BatchBegin)
}
fn batch_end() -> Message {
    batch_msg(ControlMessage::BatchEnd)
}
fn batch_msg(control: ControlMessage) -> Message {
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | NLM_F_ACK;

    // the res_id carries the nfnetlink subsystem for batch control messages
    let nft = NetfilterHeader::new(
        NetfilterProtoFamily::Unspec,
        0,
        u8::from(NetfilterSubsystem::NfTables) as u16,
    );

    NetlinkMessage::new(header, NetfilterMessage::new(nft, control).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nftables::set::SimpleSet;
    use netlink_packet_core::NetlinkPayload;
    use netlink_packet_netfilter::NetfilterMessageInner;
    use std::net::Ipv4Addr;

    fn is_control(msg: &Message, begin: bool) -> bool {
        let NetlinkPayload::InnerMessage(NetfilterMessage {
            inner: NetfilterMessageInner::None(c),
            ..
        }) = &msg.payload
        else {
            return false;
        };

        matches!(
            (c, begin),
            (ControlMessage::BatchBegin, true) | (ControlMessage::BatchEnd, false)
        )
    }

    #[test]
    fn transactions_are_bounded_and_wrapped() {
        const BATCH: usize = 128 * 1024;

        let set = SimpleSet::<Ipv4Addr>::new("t", "s", 1);
        let msgs: Vec<_> = set
            .fill((0..50_000).map(|i| Ipv4Addr::from(0x0a00_0000 + i)))
            .collect();
        let n = msgs.len();

        let txs: Vec<_> =
            Transactions::new(msgs.into_iter().map(Group::from), BATCH, usize::MAX).collect();
        assert!(txs.len() >= 2, "expected multiple transactions");

        let mut total_msgs = 0;
        for tx in &txs {
            let total: usize = tx.iter().map(|m| m.buffer_len()).sum();
            assert!(total <= BATCH, "transaction exceeds BATCH");

            assert!(is_control(&tx[0], true));
            assert!(is_control(&tx[tx.len() - 1], false));

            total_msgs += tx.len() - 2; // minus batch begin/end
        }

        // no message is dropped at a transaction boundary
        assert_eq!(total_msgs, n, "messages lost across transactions");
    }

    /// A transaction is also bounded by its message count, so a batch of many
    /// tiny messages (each producing a kernel ACK) cannot overflow the socket's
    /// receive buffer.
    #[test]
    fn transactions_are_bounded_by_message_count() {
        // huge byte budget, small message budget: only the count should split
        let max_messages = 100;
        let msgs: Vec<_> = (0..1000).map(|_| Group::from(batch_begin())).collect();

        let txs: Vec<_> = Transactions::new(msgs.into_iter(), usize::MAX, max_messages).collect();
        assert_eq!(txs.len(), 10, "1000 messages / 100 per tx");

        for tx in &txs {
            let inner = tx.len() - 2; // minus batch begin/end
            assert!(inner <= max_messages, "transaction exceeds message cap");
            assert!(is_control(&tx[0], true));
            assert!(is_control(&tx[tx.len() - 1], false));
        }
    }

    /// A group is atomic: it ends up whole in one transaction, even if it
    /// exceeds the caps. Consecutive groups share a transaction while they fit.
    #[test]
    fn transactions_never_split_a_group() {
        let group = Group::Atomic(vec![batch_begin(), batch_begin(), batch_begin()]);
        let groups = vec![
            group,
            Group::from(batch_begin()),
            Group::from(batch_begin()),
            Group::from(batch_begin()),
        ];

        // a one-message cap cannot split the three-message group
        let txs: Vec<_> = Transactions::new(groups.into_iter(), usize::MAX, 1).collect();

        assert_eq!(txs[0].len(), 5, "group split across transactions");
        assert!(is_control(&txs[0][0], true));
        assert!(is_control(&txs[0][4], false));

        // the remaining one-message groups are split by the cap
        assert_eq!(txs.len(), 4);
        for tx in &txs[1..] {
            assert_eq!(tx.len(), 3);
        }
    }
}
