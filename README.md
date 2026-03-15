 Blockchain Simulation 
blockcahin consists of blocks => block:
-> header:
1) previous block address hash.
2) time stamp of the block.
3) Merkel root - hash value that is created by combining the hash values of all transactions taken place.
4) nonce - resultant hash of the consensus algorithm (preferably proof of work).

-> body:
1) data - actual transaction data that has taken place in that block.

-> behaviour of the blocks in blockchain:
1) They are non-appendable/ deletable; they only grow in size.
2) They follow a peer-to-peer communication system.
3) They detect faulty nodes and decide to validate any new transaction based on the proof of work mechanism (computational power consumed for the transaction to be completed).
4) The nodes vote for the block to be valid or not. (Byzantine fault tolerance: for f faulty nodes, there should be 3f+1 total nodes in a stable system to reach consensus).

-> approach:
1) data structure: singly linked list and adding new blocks.
2) Verifying the previous hash and time stamp for validation of the block
3) data is going to be :
        a)name of the miner
        b)time at which mining began. [The mining time and the block time stamp should be close to each other(at least by 5 mins) for validation.]


    return 0;
}
