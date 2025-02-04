**Author: Tobias Klenze**

**Protocol: Redacted**. I originally submitted a variant of this code as an interview homework exercise, and the company does not want to make it too easy for other candidates to find existing solutions, so I am redacting the details of the protocol that is being implemented. However, if you email me, I am happy to share details. As is common in scientific communication, "We" is used, even though this implementation is entirely my own work.

This project implements the **xxx** variant of **xxx**, a simple consensus protocol. Our implementation is comprised of:
- **Protocol participants**: Implementation of the node.
- **Node-level attacker**: Different variants of node running various attacks.
- **Network Simulation**: A simulator that forwards messages between nodes, with a choice between a range of network conditions.
- **Unit Tests**: Tests under benign conditions, bad network conditions, attacking nodes, and combinations thereof.

## Running the Tests
To run a specific test, use the following command:

```bash
cargo test -- --nocapture test_honest_only_perfect_network
```
To run all the tests in the module, use the following command:

```bash
cargo test -- --nocapture
```

# Details and Evaluation
We evaluate our implementation on seven different unit tests that execute the protocol for a given number of protocol participants and for a given number of epochs. We model different types of adversarial node behavior and different types of network conditions. However, at least ⌈2n/3⌉ nodes are honest and the network conditions always reach the Global Stabilization Time, i.e., a period of synchrony, after at most half the epochs have passed.

We automatically check for consistency at the end of each execution, as defined in the paper. We also check for errors produced by our implementation that would indicate a fault of our implementation. We produce messages useful for debugging. This includes messages whenever an honest node believes to have detected malicious/faulty behavior.

Our unit tests all pass, meaning that we have confirmed consistency for the respective executions. We furthermore manually inspected the output from all unit tests, and confirmed that they provide liveness, i.e., that the protocol is able to make progress on finalization when we increase the number of epochs.

## Assumptions, limitations and simplifications
- We assume secure channels between nodes.
- We do not use cryptographic libraries for signatures, but use a dummy call to 
sign messages. However, we use sha256 for hashes.
- We assume the security of all underlying cryptographic primitives.
- We cover only limited types of faulty / attacker behavior:
    - Attacker nodes can fail and stop, not interacting with the protocol.
    - Attacker nodes can propose a new block in each epoch, even when they are not the leader.
    - Attacker nodes can vote for any block that they observe.
    - Attacker nodes can equivocate and propose two different blocks, each to one half of their peers.
    - The network can be delay messages and reorder messages. Concretely, per epoch there are two loops to deliver messages. In each loop, messages are selected with a predefined probability, shuffled, and delivered. Messages that are not selected are kept in the queue to be delivered later. Note that dropping messages is not supported by the execution model, since it could violate liveness.
- We do not address any kind of DoS attack by attacker nodes, e.g., by them flooding an honest node with votes for non-existent blocks (currently, we store all votes even if we do not have the corresponding block (yet))

## Differences between protocol and implementation
- The protocol as presented in the paper makes block proposals and block votes indistinguishable. We are unsure if this is a conscious choice, as common wisdom in protocol design is that the messages from different protocol steps should be non-unifiable, i.e., they should be different from the form of the message alone. We follow this principle and add the message type under the signature.
- Contrary to the paper, we define block proposals to have the signature on the hash of the block, as opposed to the block itself. This is more efficient, especially if the block is large.
- Instead of the term “length”, we use the term “height” to describe the distance between a given block and the genesis block. This is to avoid confusion with other types of lengths.
- We include a "name" for each block, which is helpful for debugging, but we would ultimately remove. We set it to the height "/" proposer id.

## Open tasks
- Implement proper use of cryptographic signing primitive.
- Investigate alternative hashing primitives, e.g., SHA3, for future-proofness. Alternatively, consider cryptographic agility to allow upgrades later.
- Implement more network simulators that test, for instance, a temporary partition of the network, which can be combined with an equivocation attack. Provided at least ⌈2n/3⌉ nodes are honest, this should still provide consistency. 
- Liveness check. Liveness properties in general can never be refuted in a finite execution of a protocol (since the fulfillment of the required condition can always be postponed). However, we can prove a stronger variant of this property: all honest nodes finalize a new block given a period of network stability of a certain length (we believe that this length is 6*delta, sufficient to produce three consecutive blocks in consecutive epochs, but in case there are adversarial nodes, this can only be guaranteed if all three leaders are honest). This stronger property is actually a safety property, which means that we could check for it.
- Advanced testing of attacker implementation. So far, our unit tests focus on the correct execution of the protocol under attacker actions, but we have not yet systematically tested that the attacker is correctly implemented. Instead, we manually went through the debug output of a few executions, where indeed the attackers' actions were recorded.
- process_unprocessed_pool: more testing of this method. In many of the tests, it is not being called at all, because their network model means that that a parent block is always guaranteed to arrive before its child. In real life, this is not guaranteed.
