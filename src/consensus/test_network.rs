extern crate rand;
extern crate sha2;

use super::network::Network;
use super::node::{Node, NodeTrait};
use super::utils::{Debug, Hash};
use std::collections::HashSet;

struct TestNetwork;

impl TestNetwork {
    /// All honest, perfect network conditions
    fn test_honest_only_perfect_network() {
        TestNetwork::print_test_case_header("Honest nodes only");
        let n = 4;
        let epochs = 2;
        let mut network = Network::new(n);
        TestNetwork::generate_transactions(&mut network.nodes, n);
        network.run_simple(epochs);
        TestNetwork::validate(&network);
    }

    /// All honest, synchrony, but reorder the messages
    fn test_honest_only_with_reorder() {
        TestNetwork::print_test_case_header("Honest nodes only with reordering");
        let n = 7;
        let epochs = 9;
        let mut network = Network::new(n);
        TestNetwork::generate_transactions(&mut network.nodes, n);
        network.run_reorder(epochs);
        TestNetwork::validate(&network);
    }

    /// All honest, with bad network conditions in first half
    fn test_honest_only_with_delays_then_synchrony() {
        TestNetwork::print_test_case_header("Honest nodes only with delays then synchrony");
        let n = 7;
        let epochs = 20;
        let fraction = 0.75; // Chance of delivering a message in a given round
        let mut network = Network::new(n);
        TestNetwork::generate_transactions(&mut network.nodes, n);
        network.run_delays_then_synchrony(epochs, fraction);
        TestNetwork::validate(&network);
    }

    /// One third of the nodes is stopped (no participation in protocol)
    fn test_one_third_stopped() {
        TestNetwork::print_test_case_header("One third of nodes stopped");
        let mut attacker_config = HashSet::new();
        attacker_config.insert("fail_stop".to_string());
        let n = 4;
        let epochs = 10;
        let mut network = Network::new_byzantine(n, attacker_config);
        TestNetwork::generate_transactions(&mut network.nodes, n);
        network.run_simple(epochs);
        TestNetwork::validate(&network);
    }

    /// One third of the nodes is stopped (no participation in protocol)
    /// In the network model that delays messages initially, and after half the
    /// epochs is synchronous.
    fn test_one_third_stopped_with_delays_then_synchrony() {
        TestNetwork::print_test_case_header(
            "One third of nodes stopped with delays then synchrony",
        );
        let mut attacker_config = HashSet::new();
        attacker_config.insert("fail_stop".to_string());
        let n = 4;
        let epochs = 50;
        let fraction = 0.9;
        let mut network = Network::new_byzantine(n, attacker_config);
        TestNetwork::generate_transactions(&mut network.nodes, n);
        network.run_delays_then_synchrony(epochs, fraction);
        TestNetwork::validate(&network);
    }

    /// Four nodes, one of which misbehaves in various ways,
    /// in the network model that delays messages initially, and after half the
    /// epochs is synchronous.
    fn test_one_third_misbehave_with_delays_then_synchrony() {
        TestNetwork::print_test_case_header(
            "One third of nodes misbehave with delays then synchrony",
        );
        let mut attacker_config = HashSet::new();
        attacker_config.insert("always_leader".to_string());
        attacker_config.insert("vote_everything".to_string());
        attacker_config.insert("equivocate".to_string());
        let n = 4;
        let epochs = 30;
        let fraction = 0.75;
        let mut network = Network::new_byzantine(n, attacker_config);
        TestNetwork::generate_transactions(&mut network.nodes, n);
        network.run_delays_then_synchrony(epochs, fraction);
        TestNetwork::validate(&network);
    }

    /// Four nodes, one of which misbehave in various ways,
    /// in the network model that delays messages initially, and after half the
    /// epochs is synchronous.
    fn test_one_third_fake_sigs_with_delays_then_synchrony() {
        TestNetwork::print_test_case_header(
            "One third of nodes fake signatures with delays then synchrony",
        );
        let mut attacker_config = HashSet::new();
        attacker_config.insert("always_leader".to_string());
        attacker_config.insert("fake_block_signature".to_string());
        attacker_config.insert("vote_everything".to_string());
        attacker_config.insert("equivocate".to_string());
        let n = 4;
        let epochs = 20;
        let fraction = 0.75;
        let mut network = Network::new_byzantine(n, attacker_config);
        TestNetwork::generate_transactions(&mut network.nodes, n);
        network.run_delays_then_synchrony(epochs, fraction);
        TestNetwork::validate(&network);
    }

    /// Validation means checking consistency of the chains (as defined in
    /// the paper)
    pub fn validate(network: &Network) -> bool {
        TestNetwork::print_all(network);
        assert!(TestNetwork::consistency(network));
        true
    }

    /// Check the consistency: If two blockchains are ever considered final by
    /// two honest nodes, it must be that one is a prefix of another.
    /// We show this of an execution in two steps: first, there is a unique
    /// chain that consists of exactly the finalized blocks (meaning that all
    /// of its blocks are finalized and no other blocks are finalized).
    /// Second, this chain is equal between all honest nodes.
    fn consistency(network: &Network) -> bool {
        let honest_nodes: Vec<&Node> = network
            .nodes
            .iter()
            .filter_map(|node| node.as_any().downcast_ref::<Node>())
            .collect();
        let mut finalized_chains = vec![Vec::new(); honest_nodes.len()];
        for (i, node) in honest_nodes.iter().enumerate() {
            // Starting from the highest finalized block, we construct the
            // highest finalized chain by recursively adding the parents.
            let mut block_hash = node.chain.highest_finalized_block().clone();
            finalized_chains[i].push(block_hash);
            while let Some(parent_hash) = node.chain.parent_of(block_hash) {
                block_hash = parent_hash;
                finalized_chains[i].push(block_hash);
            }

            // Consistency criterion #1: this chain consists exactly of the
            // finalized blocks
            if finalized_chains[i].iter().cloned().collect::<HashSet<_>>() != node.chain.finalized {
                TestNetwork::dbg(
                    "Finalized blocks inconsistent",
                    Some(node.id),
                    Some("SOUDNESS_ERROR"),
                );
                return false;
            }

            // We constructed the chains in opposite direction, reverse
            finalized_chains[i].reverse();
        }

        // Consistency criterion #2: When compared pairwise with each other, the
        // longest finalized chains of two honest nodes must be related by the
        // prefix relation (in either direction)
        for chain1 in &finalized_chains {
            for chain2 in &finalized_chains {
                if !TestNetwork::is_prefix(chain1, chain2)
                    && !TestNetwork::is_prefix(chain2, chain1)
                {
                    TestNetwork::dbg(
                        "Finalized chains nodes are not prefixes of another",
                        None,
                        Some("SOUDNESS_ERROR"),
                    );
                    return false;
                }
            }
        }
        true
    }

    fn generate_transactions(nodes: &mut Vec<Box<dyn NodeTrait>>, n: usize) {
        // Generate some transactions to be included in blocks
        for i in 0..1000 {
            nodes[i % n]
                .as_mut()
                .send_transaction(format!("This is transaction number {}", i));
        }
    }

    fn print_test_case_header(test_case: &str) {
        println!("==============================================");
        println!("Running test case: {}", test_case);
        println!("==============================================");
    }

    fn is_prefix(prefix: &[Hash], main_list: &[Hash]) -> bool {
        main_list.starts_with(prefix)
    }

    fn dbg(text: &str, id: Option<usize>, type_: Option<&str>) {
        Debug::dbg(text, id.unwrap_or(0), type_);
    }

    fn print_all(network: &Network) {
        println!("==============================================");
        for (i, node) in network.nodes.iter().enumerate() {
            let is_attacker = if node.is_attacker() {
                " (FAULTY/ATTACKER)"
            } else {
                ""
            };
            println!("Node #{} {}:", i, is_attacker);
            if let Some(honest_node) = node.as_any().downcast_ref::<Node>() {
                honest_node.chain.print_blockchain();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_honest_only_perfect_network() {
        TestNetwork::test_honest_only_perfect_network();
    }

    #[test]
    fn test_honest_only_with_reorder() {
        TestNetwork::test_honest_only_with_reorder();
    }

    #[test]
    fn test_honest_only_with_delays_then_synchrony() {
        TestNetwork::test_honest_only_with_delays_then_synchrony();
    }

    #[test]
    fn test_one_third_stopped() {
        TestNetwork::test_one_third_stopped();
    }

    #[test]
    fn test_one_third_stopped_with_delays_then_synchrony() {
        TestNetwork::test_one_third_stopped_with_delays_then_synchrony();
    }

    #[test]
    fn test_one_third_misbehave_with_delays_then_synchrony() {
        TestNetwork::test_one_third_misbehave_with_delays_then_synchrony();
    }

    #[test]
    fn test_one_third_fake_sigs_with_delays_then_synchrony() {
        TestNetwork::test_one_third_fake_sigs_with_delays_then_synchrony();
    }
}

pub fn main() {
    // This main function is only for running the tests manually if needed
    TestNetwork::test_honest_only_perfect_network();
    TestNetwork::test_honest_only_with_reorder();
    TestNetwork::test_honest_only_with_delays_then_synchrony();
    TestNetwork::test_one_third_stopped();
    TestNetwork::test_one_third_stopped_with_delays_then_synchrony();
    TestNetwork::test_one_third_misbehave_with_delays_then_synchrony();
    TestNetwork::test_one_third_fake_sigs_with_delays_then_synchrony();

    println!("==============================================");
    println!("If there are no errors, the tests passed.");
    println!(
        "Warning: Need to check for ERROR and SOUDNESS bugs manually in the output (using grep)."
    );
}
