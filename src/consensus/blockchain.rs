use super::utils;
use utils::{Crypto, Debug, Signature, Hash};
use hex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

pub const MAXLENGTH_TXS: usize = 10000;
pub const MAXLENGTH_SINGLE_TX: usize = 2000;


/// A block is represented by the parent hash, epoch number, and the
/// transaction string txs. We additionally give it a name and store the
/// children, parent, and the height. This information could be re-computed on
/// the fly.
#[derive(Clone, Debug)]
pub struct Block {
    pub parent_hash: Option<Hash>,
    pub e: usize,
    pub txs: String,
    pub name: String,
    pub children: HashSet<Hash>,
    pub height: usize,
    pub hash: Hash,
}

impl Block {
    pub fn new(
        parent_hash: Option<Hash>,
        e: usize,
        txs: String,
        name: String,
        height: usize,
    ) -> Self {
        let e_bytes: Vec<u8> = Crypto::var_to_bytes(e);
        let parent_bytes: [u8; 32] = parent_hash.unwrap_or_default();
        let txs_bytes = txs.clone().into_bytes();
        let mut combined_bytes = Vec::new();
        combined_bytes.extend_from_slice(&parent_bytes);
        combined_bytes.extend_from_slice(&e_bytes);
        combined_bytes.extend_from_slice(&txs_bytes);
        let hash = Crypto::hash(&combined_bytes);

        Block {
            parent_hash,
            e,
            txs,
            name,
            children: HashSet::new(),
            height,
            hash,
        }
    }

    /// Validate a block. SIMPLIFYING ASSUMPTION: A block is valid iff its length is 
    /// < MAXLENGTH_TXS, and e is > 0. In a real blockchain, validation would obviously be more
    /// complicated.
    /// Note that this function does NOT check the validity of the signature,
    /// which is contained in BlockMessage, not in the Block itself.
    pub fn validate_block(&self) -> bool {
        self.txs.len() < MAXLENGTH_TXS && self.e > 0
    }

    /// This function converts a Block into a BlockMessage. Note that the
    /// sender and the signer are set to the same value
    pub fn to_block_message(&self, sender: usize, signature: Signature) -> BlockMessage {
        BlockMessage::new(
            sender,
            self.parent_hash,
            self.e,
            self.txs.clone(),
            self.name.clone(),
            sender,
            signature,
        )
    }

    /// This function converts a Block into a VoteMessage. Note that the
    /// sender and the signer are set to the same value
    pub fn to_vote_message(&self, sender: usize, signature: Signature) -> VoteMessage {
        VoteMessage::new(
            sender,
            self.parent_hash,
            self.e,
            self.txs.clone(),
            self.name.clone(),
            sender,
            signature,
        )
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for Block {}

impl std::hash::Hash for Block {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.hash.hash(state);
    }
}

/// Used to distinguish different message types. Used under signature.
#[derive(Debug, Serialize, Deserialize)]
pub enum MessageType {
    BlockProposal,
    Vote,
    Empty,
}

pub trait Message: fmt::Debug + Send + Sync {
    fn clone_box(&self) -> Box<dyn Message>;
    fn creator(&self) -> usize;
    fn as_any(&self) -> &dyn std::any::Any;
    fn name(&self) -> String;
}
impl Clone for Box<dyn Message> {
    fn clone(&self) -> Box<dyn Message> {
        self.clone_box()
    }
}
impl fmt::Display for dyn Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<BlockM: {}>", self.name())
    }
}

/// A message containing a proposed block, and the signature of the block's
/// creator (which might be different from the block's sender).
#[derive(Clone, Debug)]
pub struct BlockMessage {
    pub creator: usize,
    pub parent_hash: Option<Hash>,
    pub e: usize,
    pub txs: String,
    pub name: String,
    pub signer: usize,
    pub signature: Signature,
}

impl Message for BlockMessage {
    fn creator(&self) -> usize {
        self.creator
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn clone_box(&self) -> Box<dyn Message> {
        Box::new(self.clone())
    }
    fn name(&self) -> String {
        format!("<BlockM: {}>", self.name.clone())
    }
}

impl BlockMessage {
    pub fn new(
        creator: usize,
        parent_hash: Option<Hash>,
        e: usize,
        txs: String,
        name: String,
        signer: usize,
        signature: Signature,
    ) -> Self {
        BlockMessage {
            creator,
            parent_hash,
            e,
            txs,
            name,
            signer,
            signature,
        }
    }
}

impl fmt::Display for BlockMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<BlockM: {}>", self.name)
    }
}

/// A message containing a vote: a block and signature on the block by a node
/// that supports this block.
#[derive(Clone, Debug)]
pub struct VoteMessage {
    pub creator: usize,
    pub parent_hash: Option<Hash>,
    pub e: usize,
    pub txs: String,
    pub name: String,
    pub signer: usize,
    pub signature: Signature,
}

impl Message for VoteMessage {
    fn creator(&self) -> usize {
        self.creator
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn clone_box(&self) -> Box<dyn Message> {
        Box::new(self.clone())
    }
    fn name(&self) -> String {
        format!("<VoteM: {}>", self.name.clone())
    }
}

impl VoteMessage {
    fn new(
        creator: usize,
        parent_hash: Option<Hash>,
        e: usize,
        txs: String,
        name: String,
        signer: usize,
        signature: Signature,
    ) -> Self {
        VoteMessage {
            creator,
            parent_hash,
            e,
            txs,
            name,
            signer,
            signature,
        }
    }
}

impl fmt::Display for VoteMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<VoteM: {}>", self.name)
    }
}

/// This is the actual blockchain that each node keeps track of.
/// Blocks are stored in a HashMap, where the key is the hash of the block given as type Hash.
/// Instead of using references of Blocks, we mostly use the hash of the block to reference it.
pub struct Blockchain {
    // empty genesis block is stored as a hash
    pub genesis: Hash,
    // blocks are stored as a map from block hash to block
    pub blocks: HashMap<Hash, Block>,
    // votes are stored as a map from block hash to a set of node ids that voted for it
    pub votes: HashMap<Hash, HashSet<usize>>,
    // notarized blocks are stored as a set of block hashes
    pub notarized: HashSet<Hash>,
    // finalized blocks are stored as a set of block hashes
    pub finalized: HashSet<Hash>,
    // Auxiliary data structure to enable accesing the block hashes per epoch
    pub block_by_epoch: Vec<HashSet<Hash>>,
    // The id of the node that runs the blockchain. Used for debugging purposes.
    pub id: usize,
}

impl Blockchain {
    pub fn new(id: usize) -> Self {
        let genesis = Block::new(None, 0, "".to_string(), "0".to_string(), 0);
        let genesis_hash = genesis.hash;
        let mut blocks = HashMap::new();
        let mut genesis_map = HashMap::new();
        let mut genesis_set = HashSet::new();
        genesis_map.insert(genesis.hash, genesis.clone());
        genesis_set.insert(genesis.hash);
        blocks.insert(genesis.hash, genesis);

        Blockchain {
            genesis: genesis_hash,
            blocks,
            votes: HashMap::new(),
            notarized: genesis_set.clone(),
            finalized: genesis_set.clone(),
            block_by_epoch: vec![genesis_set],
            id,
        }
    }

    /// Returns if a given block is already part of the blockchain
    pub fn contains_block(&self, b: Hash) -> bool {
        self.blocks.contains_key(&b)
    }

    /// Returns the parent block hash given a block hash, or None if it does not exist
    pub fn parent_of(&self, b: Hash) -> Option<Hash> {
        self.blocks.get(&b).unwrap().parent_hash
    }

    /// Returns the highest notarized block of the chain. Note that we find it by traversing 
    /// blocks_by_epoch backwards, but the notarized block with the highest epoch number is also
    /// guaranteed to be (one of) the highest notarized blocks.
    pub fn get_highest_notarized_block(&self) -> Hash {
        for block_level in self.block_by_epoch.iter().rev() {
            for block in block_level.iter() {
                if self.notarized.contains(block) {
                    let b = self.blocks.get(block).unwrap();
                    Debug::dbg(
                        &format!(
                            "Highest notarized block is: {} of height {}",
                            b.name, b.height
                        ),
                        self.id,
                        None,
                    );
                    return block.clone();
                }
            }
        }
        self.genesis.clone()
    }

    /// Returns the highest finalized block of the chain.
    pub fn highest_finalized_block(&self) -> &Hash {
        for block_level in self.block_by_epoch.iter().rev() {
            for block in block_level.iter() {
                if self.finalized.contains(block) {
                    return block;
                }
            }
        }
        panic!("should not happen, we always have a finalized genesis");
    }

    /// Validate a given new block and extend the chain by it. 
    /// PRECONDITION: The parent block must already be part of the chain.
    pub fn validate_and_extend(&mut self, b: Block, parent_hash: Hash) -> bool {
        if !b.validate_block() && !self.contains_block(b.hash) {
            return false;
        }
        let parent = self.blocks.get_mut(&parent_hash).unwrap();
        parent.children.insert(b.hash);
        self.block_by_epoch.resize(b.e + 1, HashSet::new());
        self.block_by_epoch[b.e].insert(b.hash);
        Debug::dbg(
            &format!("added block {} of epoch {} after {}", b, parent, b.e),
            self.id,
            None,
        );
        self.blocks.insert(b.hash, b);
        self.print_blockchain();
        true
    }

    pub fn dbg(&self, m: &str, type_: Option<&str>) {
        Debug::dbg(m, self.id, type_);
    }

    /// Print blockchain for debugging purposes. We abbreviate the hash to the
    /// first two bytes for readability and mostly reference blocks by their
    /// name (not part of the actual protocol).
    pub fn print_blockchain(&self) {
        fn print_blockchain_rec(blockchain: &Blockchain, block: Hash, height: usize) {
            let b = blockchain.blocks.get(&block).unwrap();
            let own_h = &b.hash[0..2];
            let notarized = if blockchain.notarized.contains(&block) {
                " NOTARIZED"
            } else {
                ""
            };
            let finalized = if blockchain.finalized.contains(&block) {
                " FINALIZED"
            } else {
                ""
            };
            let parent_hash_str = b
                .parent_hash
                .as_ref()
                .map_or("XX".to_string(), |p| hex::encode(&p[0..2]));
            blockchain.dbg(
                &format!(
                    "{}{} ({}), parent: {}. {}{}",
                    " ".repeat(height * 4),
                    b,
                    hex::encode(own_h),
                    parent_hash_str,
                    notarized,
                    finalized
                ),
                None,
            );
            for child in &b.children {
                print_blockchain_rec(blockchain, child.clone(), height + 1);
            }
        }
        print_blockchain_rec(self, self.genesis.clone(), 0);
    }
}
