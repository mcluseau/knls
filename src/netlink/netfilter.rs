use super::Netlink;
use eyre::Result;
use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage};
use netlink_packet_netfilter::{
    NetfilterHeader, NetfilterMessage, NetfilterProtoFamily, NetfilterSubsystem,
    none::ControlMessage,
};
use netlink_proto::sys::protocols::NETLINK_NETFILTER;
use std::{future::Future, io};

pub type Message = NetlinkMessage<NetfilterMessage>;

pub fn new_link() -> io::Result<Netlink<NetfilterMessage>> {
    Netlink::<NetfilterMessage>::new(NETLINK_NETFILTER)
}

pub trait NetlinkExt {
    fn send_as_transactions(
        &self,
        msgs: impl Iterator<Item = Message> + Send,
    ) -> impl Future<Output = Result<()>> + Send;
}

impl NetlinkExt for Netlink<NetfilterMessage> {
    async fn send_as_transactions(&self, msgs: impl Iterator<Item = Message> + Send) -> Result<()> {
        self.send_transactions(Transactions::new(msgs, self.max_batch_bytes()))
            .await
    }
}

struct Transactions<I> {
    msgs: I,
    cur: Vec<Message>,
    bytes: usize,
    max_bytes: usize,
}

impl<I> Transactions<I> {
    fn new(msgs: I, max_bytes: usize) -> Self {
        // deduct tx overhead (batch begin/end messages) from max_bytes, so max_bytes is the actual
        // inner transaction max size.
        let max_bytes =
            max_bytes.saturating_sub(batch_begin().buffer_len() + batch_end().buffer_len());
        Self {
            msgs,
            max_bytes,
            cur: Self::new_tx(),
            bytes: 0,
        }
    }

    fn new_tx() -> Vec<Message> {
        vec![batch_begin()]
    }

    fn take_tx(&mut self) -> Vec<Message> {
        let mut tx = std::mem::replace(&mut self.cur, Self::new_tx());
        tx.push(batch_end());

        self.bytes = 0;

        tx
    }
}

impl<I: Iterator<Item = Message>> Iterator for Transactions<I> {
    type Item = Vec<Message>;

    fn next(&mut self) -> Option<Self::Item> {
        for msg in self.msgs.by_ref() {
            let len = msg.buffer_len();

            if self.bytes != 0 && self.bytes + len > self.max_bytes {
                let tx = self.take_tx();
                self.bytes += len;
                self.cur.push(msg);
                return Some(tx);
            }

            self.bytes += len;
            self.cur.push(msg);
        }

        // messages exhausted: emit the remaining transaction, if any
        (self.bytes != 0).then(|| self.take_tx())
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

        let txs: Vec<_> = Transactions::new(msgs.into_iter(), BATCH).collect();
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
}
