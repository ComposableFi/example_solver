# 🎉 MANTIS V0: Decentralized Cross-Chain Intents 🎉

[![License](https://img.shields.io/npm/l/svelte.svg)](LICENSE.md)
[![Twitter Follow](https://img.shields.io/twitter/follow/mantis?style=social)](https://x.com/mantis)
[![Website](https://img.shields.io/badge/website-ComposableFoundation-blue)](https://www.composablefoundation.com/)

MANTIS V0 is a cutting-edge system designed to enable seamless, decentralized interactions across multiple blockchains. It relies on **four key components** to ensure that transactions are executed efficiently, securely, and without the need for a trusted third party. Let's explore these components:

---

## 1. 🎯 The Auctioneer
The **Auctioneer** is an essential off-chain entity that orchestrates the entire transaction process. It acts as a bridge between users, solvers, and the blockchain networks. The Auctioneer’s primary roles include:

- **Receiving Intents:** Users submit transaction intents to the Auctioneer, specifying details like source and destination chains.
- **Broadcasting to Solvers:** The Auctioneer broadcasts these intents to solvers, who compete to execute the transactions.
- **Determining the Winner:** After solvers submit their bids, the Auctioneer selects the best bid based on criteria like speed, cost, and reliability.

---

## 2. 🛠️ The Solvers
**Solvers** are entities capable of executing the transactions described in the intents. They listen for intents broadcasted by the Auctioneer and decide whether to participate in the auction. The solvers’ responsibilities include:

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
   - Users submit their intents to the Auctioneer. An intent specifies the details of a transaction, including the source chain, destination chain, and other relevant parameters. This submission is the initial step in the process.

2. **📣 Auctioneer Broadcasts Intents to Solvers**
   - Once the Auctioneer receives an intent from a user, it broadcasts this intent to solvers who are listening via WebSocket. Solvers are entities that have the capability to execute the transactions described in the intents.

3. **🤔 Solvers Decide to Participate**
   - Solvers receive the intents and decide whether to participate in the auction for executing the transaction. Each solver evaluates the intent and determines if it can provide a competitive quote and successfully execute the transaction.

4. **🏆 Auctioneer Determines Winning Solver**
   - After receiving bids from participating solvers, the Auctioneer determines which solver has won the auction. The criteria for winning can include the best quote, speed, and reliability. The Auctioneer then interacts with the escrow contract on the destination chain to announce the winning solver.

5. **⚙️ Solver Executes Transaction on Destination Chain**
   - The winning solver submits a transaction on the destination chain through the escrow contract to transfer funds to the user. If the source chain and destination chain are different, the solver also sends a cross-chain message as part of the same transaction. This ensures that the transaction is recognized and processed correctly across both chains.

6. **📦 Transaction Storage in Rollup**
   - Once the transaction is executed, whether it is a cross-chain transaction or a single-domain transaction, it is stored in the rollup. The rollup is a layer that aggregates multiple transactions and stores them securely. It also maintains the logic of how the Auctioneer operates, ensuring that the entire process remains decentralized and trustless.

7. **🔐 Decentralization and Trustlessness**
   - The rollup is responsible for storing information and executing the logic that governs the Auctioneer's operations. This setup ensures that the system remains decentralized and trustless, meaning that no single entity has control over the process, and all actions can be verified independently by participants in the network.

By managing the flow of intents, broadcasting them to solvers, determining winners, and ensuring transactions are executed and stored properly, the Auctioneer facilitates seamless and secure interactions within a decentralized ecosystem.

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

# Solver Setup Instructions

## ⚠️ Important Warnings for Ethereum Solvers

- **⚠️ WARNING:** Modify `send_tx()` on Ethereum for customized gas priority. Make sure you adjust the gas settings accordingly to avoid transaction failures.

- **⚠️ WARNING:** Always use a reliable RPC. Avoid using any unreliable private pools to ensure smooth operations.

- **⚠️ WARNING:** Solvers **MUST** send ETH gas (from the **solver address**) to the Auctioner address `0x25967E0621288bc958DC282c0CA6F451b17aef1c` to pay for several `store_intent()` (with 100$ you will execute about 150 intents with gas price 1Gwei) Then, solver must send the tx hash of this transfer, solver does this manually.
```rust
curl -X POST http://composable_endpoint/prove_gas_sent      -H "Content-Type: application/json"      -d '{
           "tx_hash": "0x55.."
         }'
```

- **⚠️ WARNING:** If the Ethereum swap size is **less** than `ETH FLAT_FEE + COMMISSION` or the Solana swap size is **less** than `SOL FLAT_FEE + COMMISSION`, the solver **will not** participate in the auction.

- **⚠️ WARNING:** Solvers need to **approve** USDT to Paraswap on Ethereum using the contract address `0x216b4b4ba9f3e719726886d34a177484278bfcae` **only once**.
- **⚠️ WARNING:** Solvers need to **approve** USDT to Escrow on Ethereum using the contract address `0x3d34b4Ff589f9B97f8a5540feC1c2ABAB9D4C64c` **only once**.

- **⚠️ WARNING:** Optimize `FLAT_FEES` based on gas consumption and **optimize token approvals** to reduce unnecessary costs.

- **⚠️ WARNING:** The solver's address **must be the same** as the address used to send ETH to the Auctioner.


## 🔧 Important Configuration: `SOLVER_ADDRESSES` in `chains/mod.rs`

When setting up as a solver within the MANTIS V0 system, one crucial variable you need to pay attention to is `SOLVER_ADDRESSES` located in the `chains/mod.rs` file. This variable is vital for ensuring that your solver is correctly recognized on the blockchain networks where you are solving intents.

The `SOLVER_ADDRESSES` variable is a static array that holds the addresses your solver uses on the respective blockchains. Each entry in this array corresponds to the specific chain where you will be solving intents.

Here’s how it looks in the code:

```rust
pub static SOLVER_ADDRESSES: &[&str] = &[
    "0x...", // ethereum, MUST be the pubkey of ETHEREUM_PKEY on .env!
    "CM...", // solana
];
```

## Step 1: Fill the .env File
The first thing you need to do is fill out the `.env` file. Use the provided `env.example` as a template:
```bash
ETHEREUM_RPC="" # https
ETHEREUM_PKEY="" # we use this pkey to be the SOLVER_PRIVATE_KEY, MUST be the private key of ethereum SOLVER_ADDRESSES
SOLANA_RPC="" # https
SOLANA_KEYPAIR=""
BRIDGE_TOKEN="USDT" # USDT
COMISSION="10" # if COMISSION == "1"-> 0.01%
SOLVER_ID="" # Given by Composable
COMPOSABLE_ENDPOINT="" # ws IP address Given by Composable
```
## Step 2: Provide Gas on Ethereum chain to Auctioner
The solver must provide some gas on ethereum chain to operate. This gas is needed for the auctioner to perform operations such as declaring the auction winner and updating the highest bid, all on-chain. Note that gas is only required on the destination chain where the user intents to receive the token_out of their intent.
- On Ethereum, Auctioner charge 6$ with gas price 10Gwei per intent solved. Solver already have in count this by charging to user a flat fee of 10$, this can be mofified on `FLAT_FEES` on `routers/mod.rs`, you can even be more accurate getting the gas price on that moment.

## Step 3: Check Remaining Gas in the Auctioner
You can check how much gas is remaining in the auctioner by making this HTTP request:
```rust
curl -X GET http://composable_endpoint/get_gas_solver?0x61e3d9e355e7cef2d685adf4d917586f9350e298 
```

## Step 4: Run the Solver
To run the solver, use the following command:
```sh
cargo run --release
```
this is the kind of messages you want to see if you made things right:
```rust
Object {
    "code": Number(3),
    "msg": String("Solver was succesfully registered"),
}

Object {
    "code": Number(1),
    "msg": Object {
        "intent": "...", // intent_info
        "intent_id": String("RVcwGSrL"),
    },
}

User wants 20000000, you can provide 95137240

Object {
    "code": Number(4),
    "msg": Object {
        "amount": Number(95137240),
        "intent_id": String("RVcwGSrL"),
        "msg": String("You won this auction!"),
    },
}

You have win 29.196523 USDT on intent RVcwGSrL
```

Inside the `example_solver`, we have two main folders: `routers` and `chains`.

### Routers
In the `routers` folder, we have Jupiter on Solana and Paraswap on Ethereum mainnet. Feel free to add more routers or your own router system. The `routers` folder doesn't need modifications unless you want to add new routers or your own router.

### Chains
In the `chains` folder, we have two chains: Ethereum and Solana. The structure is the same for each chain. The important functions are:
- `chain_simulate_swap()`
- `chain_executing()`

#### `chain_simulate_swap()`
This function is used to participate in the auction. Inside this function, you will find the logic to simulate swaps on Jupiter for Solana and Paraswap for Ethereum. Feel free to change this if you want to add more routers.

#### `chain_executing()`
This function is used when the solver wins the auction and is solving the intent. Inside this function, you will find the process to make a swap on Paraswap or Jupiter. Feel free to change this as well.

## WS:
**Composable Endpoint:**  
`ws://34.78.217.187:8900`  🏗️  upgrading to V1

### Register Solver Addresses (one address per chain)
```rust
{        
   "code": 1,
   "msg": { 
             "solver_id": SOLVER_ID, // Given by Composable
             "solver_addresses": SOLVER_ADDRESSES, // vec!(solana address, ethereum address, ...)
             "intent_hash": "...", // Keccak256Hash of the intent 
             "signature": "..." // ECDSA signature of the hash
          }
}
```
### Response:
**OK:**
```rust
{
   "code": 3,
   "msg": "Solver was successfully registered"
}
```

**ERROR:**
```rust
{
   "code": 0,
   "msg": msg_error
}
```

### Participate in an Intent Auction:
```rust
{
   "code": 2,
   "msg": {
             "intent_id": intent_id, // obtained listening to Intents
             "solver_id": SOLVER_ID, // Given by Composable
             "amount": "...", // off-chain solver setup to get the best quote
             "intent_hash": "...", // Keccak256Hash of the intent 
             "signature": "..." // ECDSA signature of the hash      
          }
}
```

### Response:
**OK:**
```rust
{
   "code": 4,
   "msg": msg // "You won this auction!"
              // OR "You lost this auction"
}
```

**ERROR:**
```rust
{
   "code": 0,
   "msg": msg_error
}
```





