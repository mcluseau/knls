use netlink_packet_core::{NLM_F_ACK, NLM_F_CREATE, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage};
use netlink_packet_netfilter::{
    NetfilterMessage,
    nftables::{NfTablesMessage, TableAttribute, TableMessage},
};

use super::set::nft_header;

/// The messages recreating (and thus emptying) an `inet` table.
///
/// Equivalent to the nft script `table X {}; delete table X; table X {}`, in a
/// single transaction: the first create cannot fail, the delete removes every
/// set/chain, and the last create leaves a fresh empty table. Merging these
/// with the set definitions puts the whole thing in one atomic batch.
pub fn recreate(table: &str) -> [NetlinkMessage<NetfilterMessage>; 3] {
    [new_table(table), delete_table(table), new_table(table)]
}

fn new_table(table: &str) -> NetlinkMessage<NetfilterMessage> {
    let mut header = NetlinkHeader::default();
    // No NLM_F_EXCL: creating an existing table is not an error.
    header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;

    let msg = NfTablesMessage::NewTable(TableMessage {
        attributes: vec![TableAttribute::Name(table.to_string())],
    });

    NetlinkMessage::new(header, NetfilterMessage::new(nft_header(), msg).into())
}

fn delete_table(table: &str) -> NetlinkMessage<NetfilterMessage> {
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | NLM_F_ACK;

    let msg = NfTablesMessage::DeleteTable(TableMessage {
        attributes: vec![TableAttribute::Name(table.to_string())],
    });

    NetlinkMessage::new(header, NetfilterMessage::new(nft_header(), msg).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::NetlinkPayload;
    use netlink_packet_netfilter::{NetfilterMessageInner, nftables::NfTablesMessage};

    fn table_msg(msg: &NetlinkMessage<NetfilterMessage>) -> &TableMessage {
        let NetlinkPayload::InnerMessage(NetfilterMessage {
            inner: NetfilterMessageInner::NfTables(NfTablesMessage::NewTable(t)),
            ..
        }) = &msg.payload
        else {
            panic!("not a NewTable message");
        };
        t
    }

    #[test]
    fn recreate_is_create_delete_create() {
        let [create1, delete, create2] = recreate("tbl");
        assert_eq!(
            table_msg(&create1).attributes,
            [TableAttribute::Name("tbl".into())]
        );
        assert!(
            matches!(
                delete.payload,
                NetlinkPayload::InnerMessage(NetfilterMessage {
                    inner: NetfilterMessageInner::NfTables(NfTablesMessage::DeleteTable(_)),
                    ..
                })
            ),
            "second message should delete the table"
        );
        assert_eq!(
            table_msg(&create2).attributes,
            [TableAttribute::Name("tbl".into())]
        );
    }
}
