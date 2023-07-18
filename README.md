# ZK Magic Square

    +-----+------+-----+
    | a0  |  a1  |  a2 |
    +-----+------+-----+
    | a3  |  a4  |  a5 |
    +-----+------+-----+
    | a6  |  a7  |  a8 |
    +-----+------+-----+

This is a Magic Square, where every row, column and diagonal should add up to a fixed {sum}, a predetermined unsigned integer.

## Zero-Knowledge Proofs (zkp)

Upon finding the solution, a valid zero-knowledge proof will be generated. The validity of the solution can be verified without revealing the solution itself.

## Verifier

The verifier can be exported as a Solidity contract, which allows for on-chain provability. (i.e building a cryptocurrency bounty system for verified puzzle solvers)
