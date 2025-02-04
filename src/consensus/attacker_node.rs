use super::blockchain::{Block, BlockMessage, Message, MessageType, VoteMessage};
use super::node::{Node, NodeTrait};
use super::utils::Crypto;
use std::any::Any;
use std::collections::HashSet;

/// This struct represents an attacker node. The attacker configuration can
/// have the following options:
///
/// attacker_config = {
///         "fail_stop" # Do not participate in the protocol
///         "always_leader", # Always proposes a block, in each epoch
///         "vote_everything", # Vote for all blocks
///         "equivocate", # Propose different blocks to different nodes
///         "fake_block_signature" # Produce blocks with an invalid signature
/// }
/// Note that (adversarial) network behavior is covered in the Network class.
pub struct AttackerNode {
    node: Node,
    attacker_config: HashSet<String>,
}
impl AttackerNode {
    pub fn new(id: usize, n: usize, attacker_config: HashSet<String>) -> Self {
        AttackerNode {
            node: Node::new(id, n),
            attacker_config,
        }
    }

    pub fn new_epoch(&mut self, e: usize) {
        // If the attacker is configured to fail-stop, it does not participate in the protocol
        if self.attacker_config.contains("fail_stop") {
            return;
        }
        // If the attacker is configured to always act like the leader, it proposes a block in each epoch
        if self.node.leader(e) == self.node.id || self.attacker_config.contains("always_leader") {
            self.propose_block(e);
        }
    }

    pub fn propose_block(&mut self, e: usize) -> Block {
        if !self.attacker_config.contains("fake_block_signature")
            && !self.attacker_config.contains("equivocate")
        {
            return self.node.propose_block(e);
        }

        let parent_hash = self.node.chain.get_highest_notarized_block().clone();
        let parent = self
            .node
            .chain
            .blocks
            .get(&parent_hash.clone())
            .unwrap()
            .clone();
        let mut name = format!("{}/{}", e, self.node.id);
        if self.attacker_config.contains("equivocate") {
            name.push_str(" equivocate #1");
        }
        let block1 = Block::new(
            Some(parent_hash.clone()),
            e,
            "1".to_string(),
            name.clone(),
            parent.height + 1,
        );
        self.node
            .chain
            .validate_and_extend(block1.clone(), parent_hash.clone());
        let signed1 = (MessageType::BlockProposal, block1.hash.clone());
        let signature1 = if !self.attacker_config.contains("fake_block_signature") {
            Crypto::sign(self.node.id as u64, &bincode::serialize(&signed1).unwrap())
        } else {
            (0, vec![])
        };
        let block1_message = block1.to_block_message(self.node.id, signature1);

        if !self.attacker_config.contains("equivocate") {
            self.broadcast_message(Box::new(block1_message));
        } else {
            let mut name2 = name.clone();
            name2.push_str(" equivocate #2");
            let block2 = Block::new(
                Some(parent.hash.clone()),
                e,
                "2".to_string(),
                name2,
                parent.height + 1,
            );
            self.node
                .chain
                .validate_and_extend(block2.clone(), parent_hash);
            let signed2 = (MessageType::BlockProposal, block2.hash.clone());
            let signature2 = if !self.attacker_config.contains("fake_block_signature") {
                Crypto::sign(self.node.id as u64, &bincode::serialize(&signed2).unwrap())
            } else {
                (0, vec![])
            };
            let block2_message = block2.to_block_message(self.node.id, signature2);
            self.node.dbg(&format!(
                "Attacker equivocating and proposing blocks {} and {}",
                block1, block2
            ));
            self.node
                .chain
                .votes
                .insert(block2.hash.clone(), HashSet::new());
            let votes = self.node.chain.votes.get_mut(&block2.hash).unwrap();
            votes.insert(self.node.id);
            self.equivocate_message(
                Box::new(block1_message) as Box<dyn Message>,
                Box::new(block2_message) as Box<dyn Message>,
            );
        }
        self.node
            .chain
            .votes
            .insert(block1.hash.clone(), HashSet::new());
        self.node
            .chain
            .votes
            .get_mut(&block1.hash)
            .unwrap()
            .insert(self.node.id);
        block1
    }

    /// This function sends two different messages to different nodes
    pub fn equivocate_message(&mut self, m1: Box<dyn Message>, m2: Box<dyn Message>) {
        for i in 0..self.node.n {
            if i != self.node.id {
                if i % 2 == 0 {
                    self.node.outgoing_messages.push_back((i, m1.clone()));
                } else {
                    self.node.outgoing_messages.push_back((i, m2.clone()));
                }
            }
        }
    }

    pub fn broadcast_message(&mut self, m: Box<dyn Message>) {
        if self.attacker_config.contains("fail_stop") {
            return;
        }
        self.node.broadcast_message(m);
    }

    pub fn incoming_message(&mut self, m: &dyn Message, j: usize) {
        if self.attacker_config.contains("fail_stop") {
            return;
        }
        if let Some(block_message) = m.as_any().downcast_ref::<BlockMessage>() {
            self.receive_block((*block_message).clone());
        } else {
            self.node.incoming_message(&*m, j);
        }
    }

    fn block_message_to_vote(&self, b: BlockMessage) -> VoteMessage {
        let signature = (self.id as u64, b.signature.clone().1);
        VoteMessage {
            creator: b.creator,
            parent_hash: b.parent_hash.clone(),
            e: b.e,
            txs: b.txs.clone(),
            name: b.name.clone(),
            signer: self.id,
            signature,
        }
    }

    pub fn receive_block(&mut self, b: BlockMessage) {
        self.node.receive_block(b.clone());
        if self.attacker_config.contains("vote_everything") {
            let vote_message = self.block_message_to_vote(b);
            self.node.broadcast_message(Box::new(vote_message));
        }
    }
}

impl std::ops::Deref for AttackerNode {
    type Target = Node;

    fn deref(&self) -> &Self::Target {
        &self.node
    }
}

impl std::ops::DerefMut for AttackerNode {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.node
    }
}

impl NodeTrait for AttackerNode {
    fn id(&self) -> usize {
        self.id
    }

    fn is_attacker(&self) -> bool {
        true
    }

    fn incoming_message(&mut self, m: &dyn Message, j: usize) {
        self.incoming_message(m, j);
    }

    fn clear_outgoing_messages(&mut self) -> Vec<(usize, Box<dyn Message>)> {
        let messages: Vec<_> = self.outgoing_messages.drain(..).collect();
        messages
    }
    fn process_unprocessed_pool(&mut self) {
        self.node.process_unprocessed_pool();
    }
    fn send_transaction(&mut self, transaction: String) {
        self.node.send_transaction(transaction);
    }
    fn new_epoch(&mut self, e: usize) {
        self.new_epoch(e);
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
