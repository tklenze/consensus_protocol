use super::blockchain::{
    Block, BlockMessage, Blockchain, Message, MessageType, VoteMessage, MAXLENGTH_SINGLE_TX,
    MAXLENGTH_TXS,
};
use super::utils::{Crypto, Debug, Signature, Hash};
use bincode;
use std::any::Any;
use std::collections::{HashSet, VecDeque};
use std::fmt;

/// This trait defines the interface that a node must implement. It is implemented by:
/// Node, the normal node, and AttackerNode, the attacker node.
pub trait NodeTrait {
    // The node identifier (validator ID)
    fn id(&self) -> usize;
    // Whether the node is an attacker (true in AttackerNode struct)
    fn is_attacker(&self) -> bool;
    // Invoked whenever the node receives a message m from the j-th node.
    fn incoming_message(&mut self, m: &dyn Message, j: usize);
    // Returns the messages queued for sending and clears the queue
    fn clear_outgoing_messages(&mut self) -> Vec<(usize, Box<dyn Message>)>;
    // Process those messages that we previously could not process (e.g. block whose parent we have 
    // not received yet)
    fn process_unprocessed_pool(&mut self);
    // Users send transactions to be included in the blockchain
    fn send_transaction(&mut self, transaction: String);
    // Invoked whenever a new epoch e begins. Leader proposes a block.
    fn new_epoch(&mut self, e: usize);
    fn as_any(&self) -> &dyn Any;
}

/// This struct represents an honest node. The struct AttackerNode implements the same NodeTrait and
/// uses some functions of this struct, but overwrites some of them behavior.
/// The protocol proceeds in three phases:
/// 1. Leader phase: Each node determines the leader of the current epoch. The
///    leader proposes a new block.
/// 2. Vote phase: disseminate blocks, vote for them, and notarize blocks with
///    sufficiently many votes.
/// 3. Finalize phase: finalize blocks given the finalization rule.
pub struct Node {
    // The node identifier (validator ID)
    pub id: usize,
    // The total number of validators
    pub n: usize,
    // The blockchain
    pub chain: Blockchain,
    // Outgoing messages, which are queued and sent in batches
    pub outgoing_messages: VecDeque<(usize, Box<dyn Message>)>,
    // Messages that we previously could not process
    unprocessed_pool: VecDeque<Box<dyn Message>>,
    // The transaction pool, populated by users, drained by including transactions in blocks
    tx_pool: VecDeque<String>,
}

impl Node {
    pub fn new(id: usize, n: usize) -> Self {
        Node {
            id,
            n,
            chain: Blockchain::new(id),
            outgoing_messages: VecDeque::new(),
            unprocessed_pool: VecDeque::new(),
            tx_pool: VecDeque::new(),
        }
    }

    /// Invoked whenever the node receives a message m from the j-th node.
    /// Right now, we ignore the sender j. Note that the sender j might be
    /// different from the creator of the message, m.creator, in case it was
    /// relayed.
    pub fn incoming_message(&mut self, m: &dyn Message, j: usize) {
        if let Some(block_message) = m.as_any().downcast_ref::<BlockMessage>() {
            self.receive_block((*block_message).clone());
        } else if let Some(vote_message) = m.as_any().downcast_ref::<VoteMessage>() {
            self.receive_vote((*vote_message).clone());
        }
    }

    /// Send a message m to all peers
    pub fn broadcast_message(&mut self, m: Box<dyn Message>) {
        for i in 0..self.n {
            if i != self.id {
                self.outgoing_messages.push_back((i, m.clone()));
            }
        }
    }

    /// Computes the leader id of round e based on a Hash function. Concretely,
    /// sha256(e) mod n.
    pub fn leader(&self, e: usize) -> usize {
        Crypto::short_hash(&Crypto::sha256_var(e)) as usize % self.n
    }

    /// Invoked whenever a new epoch e begins. Leader proposes a block.
    pub fn new_epoch(&mut self, e: usize) {
        if self.leader(e) == self.id {
            self.propose_block(e);
        }
    }

    /// Build block txs: start with own id, then include transactions.
    fn build_block_txs(&mut self, id: usize) -> String {
        let mut txs = id.to_string();
        while !self.tx_pool.is_empty() && self.tx_pool[0].len() + txs.len() < MAXLENGTH_TXS {
            let tx = self.tx_pool.pop_front().unwrap();
            txs.push_str(&tx);
        }
        txs
    }

    /// Build a block.
    fn build_block(&mut self, parent_hash: Hash, e: usize) -> Block {
        // Build block payload from transactions
        let txs = self.build_block_txs(self.id);
        // Name is a handy string for debugging purposes, can remove for final protocol.
        let name = format!("{}/{}", e, self.id);
        let parent_height = self.chain.blocks.get(&parent_hash).unwrap().height;
        Block::new(Some(parent_hash), e, txs, name, parent_height + 1)
    }

    /// This node is the leader for this epoch, propose a new block
    pub fn propose_block(&mut self, e: usize) -> Block {
        self.dbg(&format!("I am the leader for epoch {}", e));
        self.chain.print_blockchain();
        let parent_hash = self.chain.get_highest_notarized_block().clone();

        // Construct new block, validate it and extend the blockchain by it.
        let new_block = self.build_block(parent_hash, e);
        self.chain
            .validate_and_extend(new_block.clone(), parent_hash);
        self.dbg(&format!(
            "Proposing new block {}, child of {}",
            new_block,
            self.chain.blocks.get(&parent_hash).unwrap()
        ));

        // Add self-vote for this block
        let mut vote_set = HashSet::new();
        vote_set.insert(self.id);
        self.chain.votes.insert(new_block.hash, vote_set);

        // Broadcast block
        let signed = (MessageType::BlockProposal, new_block.hash);
        let signed_bytes = bincode::serialize(&signed).unwrap();
        let signature: Signature = Crypto::sign(self.id as u64, &signed_bytes);
        let broadcast_message = new_block.to_block_message(self.id, signature);
        self.broadcast_message(Box::new(broadcast_message));
        new_block
    }

    /// This node receives a block, validates it, adds it to its chain, and in
    /// some cases votes for it
    pub fn receive_block(&mut self, b: BlockMessage) {
        if b.parent_hash.is_none() {
            self.dbg_type(
                &format!("Received block {} with no parent hash", b),
                Some("ATTACK"),
            );
            return;
        }
        // If we don't have the parent, we cannot validate and process this
        // block
        let parent = self.chain.blocks.get(b.parent_hash.as_ref().unwrap());
        if parent.is_none() {
            self.dbg(&format!(
                "We cannot process {}, adding to unprocessed_pool",
                b
            ));
            self.unprocessed_pool.push_back(Box::new(b));
            return;
        }
        let parent = parent.unwrap();

        // Check that signer is the leader
        if b.signer != self.leader(b.e) {
            self.dbg_type(
                &format!(
                    "Received block {} from {}, but leader of epoch {} is {}",
                    b,
                    b.signer,
                    b.e,
                    self.leader(b.e)
                ),
                Some("ATTACK"),
            );
            return;
        }

        // Create block based on the block message
        let new_block = Block::new(
            Some(b.parent_hash.as_ref().unwrap().clone()),
            b.e,
            b.txs.clone(),
            b.name.clone(),
            parent.height + 1,
        );
        if self.chain.contains_block(new_block.hash) {
            return;
        }

        // Check signature
        // FIXME: this should be done before we store the block in the unprocessed_pool (not 
        // required for soundness, but to limit the number of messages we store).
        let signed = (MessageType::BlockProposal, new_block.hash);
        let signed_bytes = bincode::serialize(&signed).unwrap();
        if !Crypto::check_signature(b.signer as u64, &signed_bytes, &b.signature) {
            self.dbg_type("Signature check failed", Some("ATTACK"));
            return;
        }

        // Add block to the chain after validating it. If it does not validate, ignore it.
        if !self
            .chain
            .validate_and_extend(new_block.clone(), parent.hash)
        {
            return;
        }

        // A block proposal is itself also a vote for this block, so add it to our votes
        if !self.chain.votes.contains_key(&new_block.hash) {
            self.chain
                .votes
                .insert(new_block.hash, HashSet::new());
        }
        self.chain
            .votes
            .get_mut(&new_block.hash)
            .unwrap()
            .insert(b.signer);

        // Determine if we are going to vote for the block
        let notarization_height = self
            .chain
            .blocks
            .get(&self.chain.get_highest_notarized_block())
            .unwrap()
            .height;
        if new_block.height == notarization_height + 1 {
            self.vote(new_block.clone());
            self.dbg(&format!(
                "Voting for block {} of height {}",
                new_block, new_block.height
            ));
        } else {
            self.dbg(&format!("Not voting for block {} of height {} since it does not advance 
            max notarization height of {}", new_block, new_block.height, notarization_height));
        }

        // Relay block message to other peers
        self.broadcast_message(Box::new(b));
    }

    /// Attempt to vote for a block
    pub fn vote(&mut self, b: Block) {
        // Check if this is the only block of this epoch that we know of
        if self.chain.block_by_epoch[b.e].len() > 1 {
            self.dbg(&format!(
                "Not voting for {} since epoch {} has more blocks: {:?}",
                b, b.e, self.chain.block_by_epoch[b.e]
            ));
            return;
        }

        // Add vote to set of received votes
        if !self.chain.votes.contains_key(&b.hash) {
            self.chain.votes.insert(b.hash, HashSet::new());
        }
        self.chain.votes.get_mut(&b.hash).unwrap().insert(self.id);

        // Attempt to notarize based on existing votes
        self.notarize(b.hash);

        // Broadcast vote
        let signed = bincode::serialize(&(MessageType::Vote, b.hash)).unwrap();
        let signature = Crypto::sign(self.id as u64, &signed);
        let vote_message = b.to_vote_message(self.id, signature);
        self.broadcast_message(Box::new(vote_message));
    }

    /// We have received a vote message. Ignore if we already received it
    /// or if its faulty. Else, add to vote set and relay, then attempt to
    /// notarize the block and finalize its parent.
    pub fn receive_vote(&mut self, b: VoteMessage) {
        // We might not have received the block yet, so just create a dummy
        // block and we will store the vote under the dummy vote's hash (which
        // is equal to the real block's hash)
        if b.parent_hash.is_none() {
            self.dbg_type(
                &format!("Received vote {} with no parent hash", b),
                Some("ATTACK"),
            );
            return;
        }
        let new_block = Block::new(
            Some(b.parent_hash.as_ref().unwrap().clone()),
            b.e,
            b.txs.clone(),
            b.name.clone(),
            0,
        );
        // Setup
        if !self.chain.votes.contains_key(&new_block.hash) {
            self.chain
                .votes
                .insert(new_block.hash, HashSet::new());
        }

        // Check if we have already received this vote, in which case ignore
        if self
            .chain
            .votes
            .get(&new_block.hash)
            .unwrap()
            .contains(&b.signer)
        {
            return;
        }

        // Check the cryptographic validity of the vote
        let signed = (MessageType::Vote, new_block.hash);
        let signed_bytes = bincode::serialize(&signed).unwrap();
        if !Crypto::check_signature(b.signer as u64, &signed_bytes, &b.signature) {
            self.dbg_type("Signature check failed", Some("ATTACK"));
            return;
        }

        self.dbg(&format!(
            "We received a vote for message of height {}, created by {}. Block: {}",
            new_block.height, b.creator, new_block
        ));

        // Add vote to set of received votes
        self.chain
            .votes
            .get_mut(&new_block.hash)
            .unwrap()
            .insert(b.signer);

        // Relay vote message to other peers
        self.broadcast_message(Box::new(b));

        // Attempt to notarize based on existing votes
        // For this, we need the real block, not the dummy.
        if let Some(block) = self.chain.blocks.get(&new_block.hash) {
            self.notarize(block.hash);
        }
    }

    /// Attempt to notarize a block given the stored votes
    pub fn notarize(&mut self, block_hash: Hash) {
        let block = self.chain.blocks.get(&block_hash).unwrap();
        // We need more than 2n/3 votes in order to notarize
        if !self.chain.contains_block(block_hash)
            || self.chain.votes.get(&block_hash).unwrap().len()
                < (self.n as f64 * 2.0 / 3.0) as usize
        {
            return;
        }
        self.dbg(&format!(
            "Notarizing block {} with parent {:?}",
            block,
            self.chain
                .blocks
                .get(&self.chain.parent_of(block_hash).unwrap())
                .unwrap()
                .name
        ));
        self.chain.notarized.insert(block_hash);

        // Attempt to finalize parent
        if block.parent_hash.is_none() {
            self.dbg_type(
                &format!("Local block {} has no parent", block),
                Some("SOUDNESS_ERROR"),
            );
            return;
        }
        self.finalize(block.parent_hash.unwrap(), block.e - 1);
    }

    /// Attempt to finalize a notarized block b.
    /// Precondition: b has a notarized child of epoch e+1
    pub fn finalize(&mut self, block_hash: Hash, e: usize) {
        // Already finalized (this only happens for genesis)
        if self.chain.finalized.contains(&block_hash) {
            return;
        }

        // Parent must be notarized
        let block = self.chain.blocks.get(&block_hash).unwrap();
        let parent_hash = block.parent_hash.as_ref().unwrap();
        let parent = self.chain.blocks.get(parent_hash).unwrap();
        if !self.chain.notarized.contains(parent_hash) {
            self.dbg_type(
                "Parent of notarized block undefined or not notarized",
                Some("ERROR"),
            );
            return;
        }

        // b must be notarized
        if !self.chain.notarized.contains(&block_hash) {
            self.dbg_type(
                "Block about to get finalized is not notarized",
                Some("ERROR"),
            );
            return;
        }

        // Finalize b if it and parent have consecutive epoch numbers.
        // Note that we already checked consecutive epoch number of child by
        // precondition.
        if block.e == e && parent.e == e - 1 {
            // Recursively finalize b and its parents
            let mut h = block_hash;
            while !self.chain.finalized.contains(&h) {
                self.chain.finalized.insert(h.clone());
                self.dbg(&format!(
                    "Finalizing block {}",
                    self.chain.blocks.get(&block_hash).unwrap()
                ));
                h = self.chain.parent_of(h).unwrap();
            }
        }
    }

    /// The unprocessed_pool contains messages that we previously could not
    /// process, e.g., a child block whose parent we have not received yet.
    /// We periodically attempt to process these messages again.
    pub fn process_unprocessed_pool(&mut self) {
        let messages: Vec<_> = self.unprocessed_pool.drain(..).collect();
        for m in messages {
            self.dbg(&format!("Processing {} from unprocessed pool", m));
            self.incoming_message(m.as_ref(), m.creator());
        }
    }

    /// Check that a given transaction is valid. As an example, we enforce a
    /// limit of MAXLENGTH_SINGLE_TX characters.
    fn validate_transaction(&self, tx: &str) -> bool {
        let over_max_length = tx.len() > MAXLENGTH_SINGLE_TX;
        if over_max_length {
            self.dbg_type(
                &format!("Can't include transaction, too large: {}", tx),
                Some("USER_ATTACK"),
            );
        }
        over_max_length
    }

    /// Invoked by a user that wants to include a transaction tx in the
    /// blockchain.
    pub fn send_transaction(&mut self, tx: String) {
        if self.validate_transaction(&tx) {
            return;
        }
        self.tx_pool.push_back(tx);
    }

    /// Shortcut for debugging output.
    pub fn dbg_type(&self, text: &str, type_: Option<&str>) {
        Debug::dbg(text, self.id, type_);
    }
    pub fn dbg(&self, text: &str) {
        Debug::dbg(text, self.id, None);
    }
}

impl NodeTrait for Node {
    fn id(&self) -> usize {
        self.id
    }

    fn is_attacker(&self) -> bool {
        false
    }

    fn incoming_message(&mut self, m: &dyn Message, j: usize) {
        self.incoming_message(m, j);
    }

    fn clear_outgoing_messages(&mut self) -> Vec<(usize, Box<dyn Message>)> {
        let messages: Vec<_> = self.outgoing_messages.drain(..).collect();
        messages
    }
    fn process_unprocessed_pool(&mut self) {
        self.process_unprocessed_pool();
    }
    fn send_transaction(&mut self, transaction: String) {
        self.send_transaction(transaction);
    }
    fn new_epoch(&mut self, e: usize) {
        self.new_epoch(e);
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}
