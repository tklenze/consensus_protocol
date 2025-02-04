use super::attacker_node::AttackerNode;
use super::blockchain::Message;
use super::node::{Node, NodeTrait};
use super::utils::Debug;
use rand::seq::SliceRandom;
use rand::{rngs::StdRng, SeedableRng, Rng};
use std::collections::{HashSet, VecDeque};

/// Simulator of network of nodes, some of which are malicious.
pub struct Network {
    pub nodes: Vec<Box<dyn NodeTrait>>,
    n: usize,
    recv_queue: Vec<VecDeque<(Box<dyn Message>, usize)>>,
    e: usize,
    rng: StdRng,
}

impl Network {
    pub fn new(number: usize) -> Network {
        let mut nodes: Vec<Box<dyn NodeTrait>> = Vec::new();
        for i in 0..number {
            nodes.push(Box::new(Node::new(i, number)));
        }
        let mut recv_queue = Vec::with_capacity(number);
        for _ in 0..number {
            recv_queue.push(VecDeque::new());
        }
        let seed: [u8; 32] = [0; 32]; // Fixed seed for deterministic behavior
        let rng = StdRng::from_seed(seed);
        Network {
            nodes,
            n: number,
            recv_queue,
            e: 0,
            rng,
        }
    }

    // Create a new network with floor(n/3) of the nodes being of attacker nodes
    pub fn new_byzantine(n: usize, attacker_config: HashSet<String>) -> Network {
        let mut nodes: Vec<Box<dyn NodeTrait>> = Vec::new();
        for i in 0..n {
            if i < (2.0 / 3.0 * n as f64) as usize {
                nodes.push(Box::new(Node::new(i, n)));
            } else {
                nodes.push(Box::new(AttackerNode::new(i, n, attacker_config.clone())));
            }
        }
        let mut recv_queue = Vec::with_capacity(n);
        for _ in 0..n {
            recv_queue.push(VecDeque::new());
        }
        let seed: [u8; 32] = [0; 32]; // Fixed seed for deterministic behavior
        let rng = StdRng::from_seed(seed);
        Network {
            nodes,
            n,
            recv_queue,
            e: 0,
            rng,
        }
    }

    pub fn send(&mut self, i: usize, m: Box<dyn Message>, j: usize) {
        self.recv_queue[j].push_back((m, i));
    }

    fn send_all(&mut self) {
        for sender in 0..self.n {
            let messages: Vec<_> = self.nodes[sender]
                .clear_outgoing_messages()
                .iter()
                .cloned()
                .collect();
            for (receiver, m) in messages {
                self.send(sender, m, receiver);
            }
        }
    }

    fn recv_all(&mut self) {
        for i in 0..self.n {
            if !self.recv_queue[i].is_empty() {
                while let Some((m, j)) = self.recv_queue[i].pop_front() {
                    self.nodes[i].incoming_message(&*m, j);
                }
            }
        }
    }

    /// In this execution, messages are perfectly arriving in order and without packet loss.
    pub fn run_simple(&mut self, epoch_limit: usize) {
        for _epoch in 0..epoch_limit {
            // New Epoch
            self.e += 1;
            self.dbg(&format!("========= New Epoch {} =========", self.e), None, Some("NETWORK"));
            for i in 0..self.n {
                self.nodes[i].new_epoch(self.e);
            }

            // Three rounds of message passing
            self.recv_all();
            self.send_all();
            self.recv_all();
            self.send_all();
            self.recv_all();
            self.send_all();

            // Nodes process messages from unprocessed_pool
            for i in 0..self.n {
                self.nodes[i].process_unprocessed_pool();
            }
        }
    }

    /// Let nodes receive all messages, but in random order
    fn recv_all_randomized(&mut self) {
        let mut randomized_queue = self.randomize_messages();
        for (m, i, j) in randomized_queue {
            self.nodes[i].incoming_message(&*m, j);
        }
    }

    /// Randomize all queued messages among all nodes
    fn randomize_messages(&mut self) -> Vec<(Box<dyn Message>, usize, usize)> {
        let mut randomized_queue = Vec::new();
        // Move all messages into the randomized_queue, along with the receiver's id
        for i in 0..self.n {
            while let Some((m, j)) = self.recv_queue[i].pop_front() {
                randomized_queue.push((m, i, j));
            }
        }
        randomized_queue.shuffle(&mut self.rng);
        randomized_queue
    }

    /// In this execution, messages are reordered randomly but sent in a way
    /// that satisfies the partial synchrony assumption of the Global
    /// Stabilization Time.
    /// Concretely, messages are delivered within delta, and each epoch lasts
    /// two delta. This should be enough to guarantee liveness.
    /// Make deterministic. Reproducible results are good for debugging.
    pub fn run_reorder(&mut self, epoch_limit: usize) {
        for _epoch in 0..epoch_limit {
            // New Epoch
            self.e += 1;
            self.dbg(&format!("========= New Epoch {} =========", self.e), None, Some("NETWORK"));
            for i in 0..self.n {
                self.nodes[i].new_epoch(self.e);
            }

            // Three rounds, but within each, nodes receive messages in random order
            self.recv_all_randomized();
            self.send_all();
            self.recv_all_randomized();
            self.send_all();
            self.recv_all_randomized();
            self.send_all();

            // Nodes process messages from unprocessed_pool
            for i in 0..self.n {
                self.nodes[i].process_unprocessed_pool();
            }
        }
    }

    /// Pick fraction many messages out of the queue, the rest remains in the queue.
    /// fraction should be in interval [0,1]
    fn pick_random_messages(&mut self, fraction: f64) -> Vec<(Box<dyn Message>, usize, usize)> {
        let mut randomized_queue = Vec::new();
        // Move all messages into the randomized_queue, along with the receiver's id
        for i in 0..self.n {
            let mut new_queue = VecDeque::new();
            while let Some((m, j)) = self.recv_queue[i].pop_front() {
                if fraction > self.rng.gen::<f64>() {
                    randomized_queue.push((m, i, j));
                } else {
                    new_queue.push_back((m, j));
                }
            }
            self.recv_queue[i] = new_queue;
        }
        randomized_queue.shuffle(&mut self.rng);
        randomized_queue
    }

    /// In this execution, in the first half of the epochs, messages are
    /// randomly delayed. The success rate of any particular message making it
    /// in round is given by fraction (between 0 and 1). There are two rounds
    /// per epoch.
    /// In the second part, messages are delivered reordered but in a
    /// synchronous way, just like in run_reorder.
    /// Make deterministic. Reproducible results are good for debugging
    pub fn run_delays_then_synchrony(&mut self, epoch_limit: usize, fraction: f64) {
        for epoch in 0..epoch_limit / 2 {
            // New Epoch
            self.e += 1;
            self.dbg(&format!("========= New Epoch {} =========", self.e), None, Some("NETWORK"));
            for i in 0..self.n {
                self.nodes[i].new_epoch(self.e);
            }

            // Round 1: Nodes receive some messages in random order
            let randomized_queue = self.pick_random_messages(fraction);
            for (m, i, j) in randomized_queue {
                self.nodes[i].incoming_message(&*m, j);
            }
            self.send_all();

            // Round 2: Nodes receive some messages in random order
            let randomized_queue = self.pick_random_messages(fraction);
            for (m, i, j) in randomized_queue {
                self.nodes[i].incoming_message(&*m, j);
            }
            self.send_all();

            // Round 3: Nodes receive some messages in random order
            let randomized_queue = self.pick_random_messages(fraction);
            for (m, i, j) in randomized_queue {
                self.nodes[i].incoming_message(&*m, j);
            }
            self.send_all();

            // Nodes process messages from unprocessed_pool
            for i in 0..self.n {
                self.nodes[i].process_unprocessed_pool();
            }
        }

        self.dbg(
            "Halfway mark reached. Network conditions are now stable.",
            None,
            Some("NETWORK"),
        );
        for epoch in 0..epoch_limit - epoch_limit / 2 {
            // New Epoch
            self.e += 1;
            for i in 0..self.n {
                self.nodes[i].new_epoch(self.e);
            }

            // Round 1: Nodes receive all messages, but in random order
            let randomized_queue = self.randomize_messages();
            for (m, i, j) in randomized_queue {
                self.nodes[i].incoming_message(&*m, j);
            }
            self.send_all();

            // Round 2: Nodes receive all messages, but in random order
            let randomized_queue = self.randomize_messages();
            for (m, i, j) in randomized_queue {
                self.nodes[i].incoming_message(&*m, j);
            }
            self.send_all();

            // Round 3: Nodes receive all messages, but in random order
            let randomized_queue = self.randomize_messages();
            for (m, i, j) in randomized_queue {
                self.nodes[i].incoming_message(&*m, j);
            }
            self.send_all();

            // Nodes process messages from unprocessed_pool
            for i in 0..self.n {
                self.nodes[i].process_unprocessed_pool();
            }
        }
    }

    fn dbg(&self, text: &str, id: Option<usize>, type_: Option<&str>) {
        Debug::dbg(text, id.unwrap_or(0), type_);
    }
}

fn main() {
    let mut network = Network::new(10);

    // Example usage
    let fraction = 0.5;
    let messages = network.pick_random_messages(fraction);
    // Do something with messages
}
