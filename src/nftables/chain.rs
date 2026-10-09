use std::fmt;

use netlink_packet_core::{
    NLM_F_ACK, NLM_F_APPEND, NLM_F_CREATE, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage,
};
use netlink_packet_netfilter::{
    NetfilterMessage,
    nftables::{
        ChainAttribute, ChainMessage, ExpressionAttribute, Hook, ListAttribute, NfTablesMessage,
        RuleAttribute, RuleMessage,
    },
};

pub use netlink_packet_netfilter::nftables::InetHookNumber;
use xxhash_rust::xxh3::Xxh3;

use super::{Message, nft_header};

/// `NF_ACCEPT`: the only base-chain policy we use (per-pod chains do the
/// filtering).
pub const ACCEPT: u32 = 1;

/// The expressions of a single rule.
pub type Rule = Vec<ListAttribute<ExpressionAttribute>>;

/// A tracked nftables chain: its `table`/`chain` names, the `add rule` messages
/// it should hold, and a streaming [xxh3](xxhash_rust::xxh3::xxh3_128) of their
/// content.
///
/// The hash is seeded with the table and chain names in [`new`](Chain::new) and
/// updated by [`push`](Chain::push) (hence by [`extend`](Chain::extend)), so
/// [`hash`](Chain::hash) is always current without any rehashing.
/// [`fill`](Chain::fill) only converts the stored rules into the messages
/// replacing the chain's content (a flush, then the rules); it does not touch
/// the hash.
#[derive(Clone)]
pub struct Chain<'t> {
    table: &'t str,
    chain: String,
    hasher: Xxh3,
    rules: Vec<Message>,
}

impl fmt::Debug for Chain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Chain")
            .field("table", &self.table)
            .field("chain", &self.chain)
            .field("hash", &self.hash())
            .field("rules", &self.rules)
            .finish()
    }
}

impl<'t> Chain<'t> {
    pub fn new(table: &'t str, chain: impl Into<String>) -> Self {
        let chain = chain.into();
        Self {
            hasher: seeded(table, &chain),
            table,
            chain,
            rules: Vec::new(),
        }
    }

    /// The table name.
    pub fn table(&self) -> &'t str {
        self.table
    }

    /// The chain name.
    pub fn chain(&self) -> &str {
        &self.chain
    }

    /// The hash of the table, chain and stored rules.
    pub fn hash(&self) -> u128 {
        self.hasher.digest128()
    }

    /// The stored `add rule` messages.
    pub fn rules(&self) -> &[Message] {
        &self.rules
    }

    /// Appends a rule and updates the hash from its message.
    pub fn push(&mut self, rule: Rule) {
        let mut msg = rule_msg(self.table, &self.chain, rule);
        msg.finalize();
        hash_message(&mut self.hasher, &msg);
        self.rules.push(msg);
    }

    /// Appends every rule of `rules` by [`push`](Chain::push)ing them.
    pub fn extend(&mut self, rules: impl IntoIterator<Item = Rule>) {
        for rule in rules {
            self.push(rule);
        }
    }

    /// Removes every stored rule and resets the hash.
    pub fn clear(&mut self) {
        self.rules.clear();
        self.hasher = seeded(self.table, &self.chain);
    }

    /// The message adding a regular (non-base) chain to the table.
    pub fn create(&self) -> Message {
        self.create_chain(None)
    }

    /// The message adding a base chain, hooked into `hook` at `priority` with
    /// `policy` (`NF_ACCEPT`/`NF_DROP`).
    pub fn create_base(&self, hook: InetHookNumber, priority: i32, policy: u32) -> Message {
        self.create_chain(Some((hook, priority, policy)))
    }

    fn create_chain(&self, base: Option<(InetHookNumber, i32, u32)>) -> Message {
        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;

        let mut attributes = vec![
            ChainAttribute::Table(self.table.to_string()),
            ChainAttribute::Name(self.chain.clone()),
        ];

        // A hook makes the kernel create a base chain (it sets NFT_CHAIN_BASE
        // itself); it needs a type and policy too, as nft emits them.
        if let Some((hook, priority, policy)) = base {
            attributes.push(ChainAttribute::Type("filter".into()));
            attributes.push(ChainAttribute::Hook(vec![
                Hook::Number(hook.into()),
                Hook::Priority(priority as u32),
            ]));
            attributes.push(ChainAttribute::Policy(policy));
        }

        let msg = NfTablesMessage::NewChain(ChainMessage { attributes });

        NetlinkMessage::new(header, NetfilterMessage::new(nft_header(), msg).into())
    }

    /// The message deleting every rule of the chain.
    ///
    /// This is the netlink form of `flush chain`. `DELRULE` carrying only the
    /// table and the chain (no rule handle nor id) makes the kernel call
    /// `nft_delrule_by_chain()`, which walks the chain and deletes all its rules.
    pub fn flush(&self) -> Message {
        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let msg = NfTablesMessage::DeleteRule(RuleMessage {
            attributes: vec![
                RuleAttribute::Table(self.table.to_string()),
                RuleAttribute::Chain(self.chain.clone()),
            ],
        });

        NetlinkMessage::new(header, NetfilterMessage::new(nft_header(), msg).into())
    }

    /// The messages replacing the chain's content: a flush, then the stored
    /// `add rule` messages.
    pub fn fill(&self) -> impl Iterator<Item = Message> {
        std::iter::once(self.flush()).chain(self.rules.iter().cloned())
    }

    /// The message deleting the chain.
    pub fn delete(&self) -> Message {
        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let msg = NfTablesMessage::DeleteChain(ChainMessage {
            attributes: vec![
                ChainAttribute::Table(self.table.to_string()),
                ChainAttribute::Name(self.chain.clone()),
            ],
        });

        NetlinkMessage::new(header, NetfilterMessage::new(nft_header(), msg).into())
    }
}

/// The `add rule` message for a rule built from `expressions`.
fn rule_msg(
    table: &str,
    chain: &str,
    expressions: impl IntoIterator<Item = ListAttribute<ExpressionAttribute>>,
) -> Message {
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND;

    let msg = NfTablesMessage::NewRule(RuleMessage {
        attributes: vec![
            RuleAttribute::Table(table.to_string()),
            RuleAttribute::Chain(chain.to_string()),
            RuleAttribute::Expressions(expressions.into_iter().collect()),
        ],
    });

    NetlinkMessage::new(header, NetfilterMessage::new(nft_header(), msg).into())
}

/// A hasher seeded with the table and chain names.
fn seeded(table: &str, chain: &str) -> Xxh3 {
    let mut hasher = Xxh3::new();
    hasher.update(table.as_bytes());
    hasher.update(&[0]);
    hasher.update(chain.as_bytes());
    hasher.update(&[0]);
    hasher
}

/// Feeds the serialized bytes of `msg` into `hasher`.
fn hash_message(hasher: &mut Xxh3, msg: &Message) {
    let mut buf = vec![0u8; msg.buffer_len()];
    msg.serialize(&mut buf);
    hasher.update(&buf);
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::NetlinkPayload;
    use netlink_packet_netfilter::NetfilterMessageInner;
    use netlink_packet_netfilter::nftables::VerdictAttribute;

    fn del_rules(msg: Message) -> Vec<RuleAttribute> {
        let NetlinkPayload::InnerMessage(NetfilterMessage {
            inner: NetfilterMessageInner::NfTables(NfTablesMessage::DeleteRule(m)),
            ..
        }) = msg.payload
        else {
            panic!("not a DeleteRule message");
        };
        m.attributes
    }

    fn new_rules(msg: &Message) -> Vec<RuleAttribute> {
        let NetlinkPayload::InnerMessage(NetfilterMessage {
            inner: NetfilterMessageInner::NfTables(NfTablesMessage::NewRule(m)),
            ..
        }) = &msg.payload
        else {
            panic!("not a NewRule message");
        };
        m.attributes.clone()
    }

    /// A dummy rule whose content depends on `n`.
    fn rule(n: u32) -> Rule {
        vec![ListAttribute::Element(vec![ExpressionAttribute::Name(
            format!("test{n}"),
        )])]
    }

    #[test]
    fn new_stores_names() {
        let chain = Chain::new("t", "c");
        assert_eq!(chain.table(), "t");
        assert_eq!(chain.chain(), "c");
        assert!(chain.rules().is_empty());
    }

    #[test]
    fn create_is_add_chain() {
        let msg = Chain::new("t", "c").create();
        assert_eq!(msg.header.flags, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE);
        let NetlinkPayload::InnerMessage(NetfilterMessage {
            inner: NetfilterMessageInner::NfTables(NfTablesMessage::NewChain(m)),
            ..
        }) = msg.payload
        else {
            panic!("not a NewChain message");
        };
        assert_eq!(
            m.attributes,
            vec![
                ChainAttribute::Table("t".into()),
                ChainAttribute::Name("c".into())
            ]
        );
    }

    #[test]
    fn flush_carries_only_table_and_chain() {
        let attrs = del_rules(Chain::new("t", "c").flush());
        // exactly table + chain, so the kernel flushes the whole chain
        assert_eq!(
            attrs,
            vec![
                RuleAttribute::Table("t".into()),
                RuleAttribute::Chain("c".into())
            ]
        );
        assert!(
            !attrs
                .iter()
                .any(|a| matches!(a, RuleAttribute::Handle(_) | RuleAttribute::Id(_))),
            "a handle/id would delete a single rule instead of flushing"
        );
    }

    #[test]
    fn push_and_extend_store_rule_messages() {
        let mut chain = Chain::new("t", "c");
        assert!(chain.rules().is_empty());

        chain.push(rule(1));
        assert_eq!(chain.rules().len(), 1);
        assert_eq!(
            new_rules(&chain.rules()[0]),
            vec![
                RuleAttribute::Table("t".into()),
                RuleAttribute::Chain("c".into()),
                RuleAttribute::Expressions(vec![ListAttribute::Element(vec![
                    ExpressionAttribute::Name("test1".into())
                ])]),
            ]
        );

        chain.extend([rule(2), rule(3)]);
        assert_eq!(chain.rules().len(), 3);
        // rule messages carry the append flag
        assert!(chain.rules()[1].header.flags & NLM_F_APPEND != 0);

        chain.clear();
        assert!(chain.rules().is_empty());
    }

    #[test]
    fn fill_of_empty_chain_is_a_single_flush() {
        let chain = Chain::new("t", "c");
        let msgs: Vec<_> = chain.fill().collect();
        assert_eq!(msgs.len(), 1);
        del_rules(msgs.into_iter().next().expect("one message"));
    }

    #[test]
    fn fill_flushes_then_adds_stored_rules() {
        let mut chain = Chain::new("t", "c");
        chain.extend([rule(1), rule(2), rule(3)]);

        let msgs: Vec<_> = chain.fill().collect();
        // flush + three rules
        assert_eq!(msgs.len(), 4);
        assert_eq!(
            del_rules(msgs[0].clone()),
            vec![
                RuleAttribute::Table("t".into()),
                RuleAttribute::Chain("c".into())
            ]
        );
        // the rest are the stored rule messages, unchanged
        for (i, msg) in msgs[1..].iter().enumerate() {
            assert_eq!(
                new_rules(msg),
                vec![
                    RuleAttribute::Table("t".into()),
                    RuleAttribute::Chain("c".into()),
                    RuleAttribute::Expressions(vec![ListAttribute::Element(vec![
                        ExpressionAttribute::Name(format!("test{}", i + 1))
                    ])]),
                ]
            );
        }
    }

    #[test]
    fn hash_updates_on_push() {
        let mut chain = Chain::new("t", "c");
        let empty = chain.hash();

        // fill does not move the hash
        let _ = chain.fill().count();
        assert_eq!(chain.hash(), empty);

        chain.push(rule(1));
        let one = chain.hash();
        assert_ne!(one, empty, "push changes the hash");

        // extend goes through push, so it also moves the hash
        chain.extend([rule(2), rule(3)]);
        assert_ne!(chain.hash(), one);
        let three = chain.hash();

        // an equivalent chain built the same way hashes alike
        let mut other = Chain::new("t", "c");
        other.extend([rule(1), rule(2), rule(3)]);
        assert_eq!(other.hash(), three);

        // a different chain name hashes differently
        let mut named = Chain::new("t", "other");
        named.extend([rule(1), rule(2), rule(3)]);
        assert_ne!(named.hash(), three);

        // clear resets to the seed
        chain.clear();
        assert_eq!(chain.hash(), empty);
    }

    #[test]
    fn fill_uses_current_rules() {
        let mut chain = Chain::new("t", "c");
        chain.extend([rule(1), rule(2), rule(3)]);

        // replacing the content changes the hash and the emitted rules
        chain.clear();
        chain.extend([rule(10), rule(20)]);
        let msgs: Vec<_> = chain.fill().collect();

        assert_eq!(msgs.len(), 3); // flush + 2 rules, not the flushed 3
        let names: Vec<_> = msgs[1..]
            .iter()
            .map(|m| match new_rules(m).pop() {
                Some(RuleAttribute::Expressions(e)) => e,
                _ => panic!("expected expressions"),
            })
            .collect();
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn grouped_rules_differ_from_separate_rules() {
        // [a, b] is one rule => one NewRule message;
        // [a], [b] is two rules => two NewRule messages.
        // The messages are self-framing (netlink header length + type), so their
        // serialized bytes differ and no explicit separator is needed.
        let mut split = Chain::new("t", "c");
        split.extend([rule_a("a"), rule_a("b")]);

        let mut joined = Chain::new("t", "c");
        joined.push(vec![
            ListAttribute::Element(vec![ExpressionAttribute::Name("a".into())]),
            ListAttribute::Element(vec![ExpressionAttribute::Name("b".into())]),
        ]);

        assert_ne!(split.hash(), joined.hash());
    }

    fn rule_a(name: &str) -> Rule {
        vec![ListAttribute::Element(vec![ExpressionAttribute::Name(
            name.into(),
        )])]
    }

    #[test]
    fn verdict_rule_serializes() {
        use netlink_packet_netfilter::nftables::{
            DataAttribute, Expressions, Immediate, Register, Verdict,
        };

        // a real-ish rule: immediate verdict accept
        let rule: Rule = vec![ListAttribute::Element(vec![
            ExpressionAttribute::Name("immediate".into()),
            ExpressionAttribute::Data(Expressions::Immediate(vec![
                Immediate::DestinationRegister(Register::Verdict),
                Immediate::Data(DataAttribute::Verdict(vec![VerdictAttribute::Code(
                    Verdict::Other(1),
                )])),
            ])),
        ])];

        let mut chain = Chain::new("t", "c");
        chain.push(rule);
        let msgs: Vec<_> = chain.fill().collect();
        assert_eq!(msgs.len(), 2); // flush + one rule
    }
}
