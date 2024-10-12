# 🎉 MANTIS V0: Decentralized Cross-Chain Intents 🎉

[![License](https://img.shields.io/npm/l/svelte.svg)](LICENSE.md)
[![Twitter Follow](https://img.shields.io/twitter/follow/mantis?style=social)](https://x.com/mantis)
[![Website](https://img.shields.io/badge/website-ComposableFoundation-blue)](https://www.composablefoundation.com/)

MANTIS V0 is a cutting-edge system designed to enable seamless, decentralized interactions across multiple blockchains. It relies on **four key components** to ensure that transactions are executed efficiently, securely, and without the need for a trusted third party. Let's explore these components:

---

## 1. 🎯 The Auctioneer
The **Auctioneer** is an essential off-chain entity that orchestrates the entire transaction process. It acts as a bridge between users, solvers, and the blockchain networks. The Auctioneer’s primary roles include:

- **Listening for Intents:** Users submit transaction intents directly on-chain, and the Auctioneer listens for these on-chain events.
- **Broadcasting to Solvers:** The Auctioneer broadcasts these intents to solvers, who compete to execute the transactions.
- **Determining the Winner:** After solvers submit their bids, the Auctioneer selects the best bid based on criteria like speed, cost, and reliability.
- **Updating the Intent:** The Auctioneer updates the on-chain intent with the winning solver and the amount output from the solver.

---

## 2. 🛠️ The Solvers
**Solvers** are entities capable of executing the transactions described in the intents. They listen for intents emitted as on-chain events and decide whether to participate in the auction. The solvers’ responsibilities include:

- **Bidding:** Solvers analyze the intents and submit bids to execute the transaction.
- **Executing Transactions:** The winning solver executes the transaction on the destination chain, ensuring the intent is fulfilled as specified.

---

## 3. 🔐 Smart Contracts on Each Chain
Smart contracts deployed on each blockchain play a pivotal role in the system. These contracts are responsible for:

- **Escrow Management:** Handling the secure transfer of funds between chains.
- **Execution Logic:** Enforcing the rules that govern how transactions are processed and validated on each chain.

These smart contracts ensure that transactions are executed in a trustless and secure manner, with no need for intermediaries.

---

## 4. 🌐 The Rollup: Where MANTIS Runs
The **Rollup** is the backbone of the MANTIS V0 system, providing a scalable and secure environment for processing transactions. It serves several critical functions:

- **Aggregation:** Collecting and storing multiple transactions in a compressed format.
- **Decentralization:** Maintaining the logic that governs the Auctioneer’s operations, ensuring the entire process remains decentralized.
- **Security:** Ensuring that all actions are transparent and can be independently verified by participants.

The Rollup enables MANTIS to operate efficiently while preserving the principles of decentralization and trustlessness.

---

# Cross-Chain Domain vs. Single Domain Options

MANTIS V0 empowers users with two flexible transaction options: **Cross-Chain Domain** and **Single Domain**. Both are designed to ensure secure, efficient, and decentralized operations, but each offers unique capabilities.

---

## 🌉 Cross-Chain Domain: Connecting the Blockchains

The **Cross-Chain Domain** lets you traverse different blockchains effortlessly. Currently, we support:

- 🟣 **Ethereum**
- 🟠 **Solana**

*(More blockchains are on the horizon!)*

### 🔄 How It Works:
In this domain, you can submit intents that involve transactions across chains. Picture this, for example:

- **🟣 Start on Ethereum:** Swap a token on Ethereum (your source chain).
- **🟠 End on Solana:** Receive the token on Solana (your destination chain).

### 🚀 The Role of Solvers:
Solvers are the unsung heroes making these cross-chain journeys possible. They:

- 🛠️ **Bridge the Gap:** By holding **USDT**, solvers enable swift and secure cross-chain swaps.
- ⏩ **Ensure Speed:** Solvers are positioned in the middle, ensuring that cross-chain intents are completed quickly.

This option is perfect for users looking to move assets between blockchains seamlessly.

---

## 🔗 Single Domain: Mastering a Single Chain

For those who prefer to stay within one blockchain, the **Single Domain** is your go-to. It supports:

- 🟣 **Ethereum**
- 🟠 **Solana**

*(And yes, more chains will be available soon!)*

### 📈 How It Works:
In the Single Domain, users submit intents and solvers execute them entirely within the same blockchain. Whether you're trading or performing other operations, it all happens within a single chain’s ecosystem.

### 🛡️ Security & Efficiency:
Both Single Domain and Cross-Chain Domain options are designed with the highest standards of security and efficiency, ensuring peace of mind for both users and solvers.

---

# 🔄 Interaction Flow

1. **👥 User Submits Intents**
   - The user submits their intent on-chain, specifying the details of a transaction, including the source chain, destination chain, and other relevant parameters. This submission is the initial step in the process.

2. **📣 Auctioneer and Solvers Listen for Intents**
   - The Auctioneer and solvers listen for on-chain events emitted after the user submits their intent. Solvers, who are capable of executing the transactions, receive the intent and decide whether to participate in the auction.

3. **🤔 Solvers Decide to Participate**
   - Solvers receive the intent and determine if they can provide a competitive bid to execute the transaction.

4. **🏆 Auctioneer Determines Winning Solver**
   - After receiving bids from participating solvers, the Auctioneer selects the winning solver based on criteria such as speed, cost, and reliability.
   - The Auctioneer then updates the on-chain intent with the winning solver and the `amount_out`.

5. **⚙️ Solver Executes Transaction on Destination Chain**
   - The winning solver submits a transaction on the destination chain through the escrow contract to transfer funds to the user. If the source chain and destination chain are different, the solver also sends a cross-chain message as part of the same transaction. This ensures that the transaction is recognized and processed correctly across both chains.

6. **📦 Transaction Storage in Rollup**
   - Once the transaction is executed, whether it is a cross-chain transaction or a single-domain transaction, it is stored in the rollup. The rollup is a layer that aggregates multiple transactions and stores them securely. It also maintains the logic of how the Auctioneer operates, ensuring that the entire process remains decentralized and trustless.

7. **🔐 Decentralization and Trustlessness**
   - The rollup is responsible for storing information and executing the logic that governs the Auctioneer's operations. This setup ensures that the system remains decentralized and trustless, meaning that no single entity has control over the process, and all actions can be verified independently by participants in the network.

---

## 🪙 User - Solver - Token Workflow

### 🚀 Single Domain Workflow:
1. **User Actions**:
   - The user escrows `token_in` on the Escrow Contract (`Escrow SC`) within the same domain.
  
2. **Solver Actions**:
   - The solver calls `send_funds_to_user()`, which triggers the following actions:
     - Sends `token_out` to the user. 
     - Receives the `token_in` from the escrow in the **SAME** transaction.

3. **Smart Contract Role**:
   - The `Escrow SC` ensures that everything is decentralized 🕸️ and operates according to the intent information submitted by the user, guaranteeing that both the solver and the user experience the same level of fairness ⚖️.

### 🌐 Cross-Domain Workflow:
1. **User Actions**:
   - The user escrows `token_in` on the **source chain** via the Escrow Contract (`Escrow SC`).

2. **Solver Actions**:
   - The solver calls `send_funds_to_user()` on the **destination chain**. This function does the following:
     - Sends `token_out` to the user.
     - Sends a cross-chain message 📨 within the **SAME** function, according to the intent info instructions, to ensure fairness for both the solver and the user.

3. **Cross-Chain Message**:
   - The message contains the necessary information to release the `token_in` on the source chain for the solver, ensuring that everything is handled fairly across domains 🔄.

---

## 🔑 Message Signing Process

1. **Keccak Hashing:**  
   - The first step is to generate a unique hash of the message. This is done using the Keccak-256 algorithm, which produces a fixed-size 256-bit hash.

2. **Signing the Message:**  
   - The solver then signs this hashed message using their Ethereum private key. This signature is a cryptographic proof that the message was indeed created by the owner of the private key.

3. **Verification by Auctioneer:**  
   - When the auctioneer receives the signed message, it verifies the signature. This is done by comparing the Ethereum address that corresponds to the private key (from which the signature was derived) with the address provided in the `SOLVER_ADDRESSES`.
   - If the addresses match, the auctioneer confirms that the message is authentic and that it was sent by the correct solver.

---
