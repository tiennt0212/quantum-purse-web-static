# QuantumPurse
A CKB quantum resistant wallet.

```
+------------------+
|     Frontend     |  - User interacts here.
+------------------+
         ^
         |
         v
+------------------+
|  QuantumPurse.ts |  - Manages wallet logic (e.g., addresses, balances, transactions).
+------------------+
         ^
         |
         v
+------------------+
|   KeyVault(WASM) |  - Processes all key operations in a sandboxed environment:
|                  |    * Generates BIP39 mnemonic.
|                  |    * Derives SPHINCS+ key pairs..
|                  |    * Encrypts, Decrypts and signs transactions.
+------------------+
         ^
         |
         v
+------------------+
|    IndexedDB     |  - Stores sensitive data, always encrypted:
|                  |    * Encrypted BIP39 mnemonic.
|                  |    * Encrypted SPHINCS+ key pairs.
+------------------+
```

## Prerequisited
1. Rust and Cargo, follow [this link](https://doc.rust-lang.org/cargo/getting-started/installation.html#:~:text=Install%20Rust%20and%20Cargo,rustup%20will%20also%20install%20cargo%20.) for installation.
2. wasm-pack, execute: `cargo install wasm-pack`.
3. Docker Engine/Desktop.
4. Node

## How to use

```shell
# Install all dependencies
npm install

# Run test - Docker REQUIRED!
npm run test

# Run in development env
npm run start

# Build a production package
npm run build

# Deploy the web app to your github
npm run deploy
```

## Usage Example 1 - Creating a new wallet with a new seed phrase.

Below is a sample code snippet demonstrating how to initialize a new wallet in `src/index.ts`:

```typescript
import "./styles.css";
import Icon from "./icon.png";
import { transfer } from "./core/transaction_builder";
import { sendTransaction } from "./core/utils";
import { NODE_URL } from "./core/config";
import QuantumPurse from "./core/quantum_purse";
import { utf8ToBytes, bytesToUtf8 } from "./core/utils";

// Add title
const text = "A quantum resistant wallet for ckb blockchain";
const $content = document.querySelector("#content");
if ($content) {
  $content.textContent = text;
}

// Add the icon
const myIcon = new Image();
myIcon.src = Icon;
document.body.appendChild(myIcon);

/////////////////////////////////////////////////////////////////////
async function run() {
  const passwordStr = "my password is easy to crack. Don't use this!";
  try {
    const wallet = await QuantumPurse.getInstance();

    // await wallet.dbClear();
    await wallet.init(utf8ToBytes(passwordStr)); // gen and ecrypt master seed; input password is gone frome here
    await wallet.genAccount(utf8ToBytes(passwordStr)); // gen and encrypt a child key; input password is gone from here

    const address = await wallet.getAddress(); // pointing to the previously generated account
    console.log("address: ", address);

    // get accounts list
    const accountList = await wallet.getAllAccounts();
    console.log("account_list: ", accountList);

    // set account pointer to account 0
    await wallet.setAccPointer(accountList[0]);
    const address0 = await wallet.getAddress();
    console.log("new_address: ", address0);

    // get balance
    const balance = await wallet.getBalance();
    console.log("balance: ", balance/100000000n, "CKB");

    // export to see the seed phrase
    const seed = await wallet.exportSeedPhrase(utf8ToBytes(passwordStr)); // !! remember to clear seed !!
    console.log("exported seed: ", bytesToUtf8(seed));

    // // import seed phrase
    // const newPasswordStr = "my password is getting strongger, right?";
    // const newSeed = "comic betray load year input cruise output lock slender glory agree wink bleak topple wheel trigger pelican clap chat learn right situate oppose lava";
    // await wallet.importSeedPhrase(utf8ToBytes(newSeed), utf8ToBytes(newPasswordStr))

    // // re-export seed phrase
    // const newExportedSeed = await wallet.exportSeedPhrase(utf8ToBytes(newPasswordStr)); // !! remember to clear seed !!
    // console.log("new exported seed: ", bytesToUtf8(newExportedSeed));

    const tx = await transfer(address0, address0, "333");
    const signedTx = await wallet.sign(tx, utf8ToBytes(passwordStr));
    const txId = await sendTransaction(NODE_URL, signedTx);
    console.log("tx_id: ", txId);

  } catch (error) {
    console.error("ERROR:", error);
  }
}

run();
/////////////////////////////////////////////////////////////////////
```

## Usage Example 1 - Importing an existing seed phrase to wallet.

Below is a sample code snippet demonstrating how to import a seed phrase to quantum purse wallet in `src/index.ts`:

```typescript
import "./styles.css";
import Icon from "./icon.png";
import { transfer } from "./core/transaction_builder";
import { sendTransaction } from "./core/utils";
import { NODE_URL } from "./core/config";
import QuantumPurse from "./core/quantum_purse";
import { utf8ToBytes, bytesToUtf8 } from "./core/utils";

// Add title
const text = "A quantum resistant wallet for ckb blockchain";
const $content = document.querySelector("#content");
if ($content) {
  $content.textContent = text;
}

// Add the icon
const myIcon = new Image();
myIcon.src = Icon;
document.body.appendChild(myIcon);

/////////////////////////////////////////////////////////////////////
async function run() {
  const passwordStr = "my password is easy to crack. Don't use this!";
  try {
    const wallet = await QuantumPurse.getInstance();

    // await wallet.dbClear();

    // importing a seed phrase
    const newSeed = "ball slush siren skirt local odor gather settle green remind orphan keep vapor comfort hen wave conduct phrase torch address hungry clerk caught vessel";
    await wallet.importSeedPhrase(utf8ToBytes(newSeed), utf8ToBytes(passwordStr));

    // export to see the seed phrase + gen first account
    const seed = await wallet.exportSeedPhrase(utf8ToBytes(passwordStr)); // !! remember to clear seed !!
    console.log("imported seed: ", bytesToUtf8(seed));
    await wallet.genAccount(utf8ToBytes(passwordStr)); // gen and encrypt a child key; input password is gone from here

    // get accounts list
    const accountList = await wallet.getAllAccounts();
    console.log("account_list: ", accountList);

    // set account pointer to account 0
    await wallet.setAccPointer(accountList[0]);
    const address0 = await wallet.getAddress();
    console.log("address0: ", address0);

    // get balance
    const balance = await wallet.getBalance();
    console.log("balance: ", balance/100000000n, "CKB");

    // build transaction and send
    const tx = await transfer(address0, address0, "333");
    const signedTx = await wallet.sign(tx, utf8ToBytes(passwordStr));
    const txId = await sendTransaction(NODE_URL, signedTx);
    console.log("tx_id: ", txId);

  } catch (error) {
    console.error("ERROR:", error);
  }
}

run();
/////////////////////////////////////////////////////////////////////
```