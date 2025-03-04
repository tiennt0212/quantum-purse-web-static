# QuantumPurse 0.0.1
A CKB quantum resistant wallet.

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

## For testing and contribution
 - prerequisites: Docker



## Usage Example

Below is a sample code snippet demonstrating how to use the core functionality in `src/index.ts`:

```typescript
import './styles.css';
import Icon from './icon.png';
import { transfer } from "./core/transaction_builder";
import { sendTransaction } from "./core/utils";
import { NODE_URL } from "./core/config";
import { utf8ToBytes } from "@noble/hashes/utils";
import QuantumPurse from './core/quantum_purse';

// Add title
const text = 'A quantum resistant wallet for ckb blockchain';
const $content = document.querySelector('#content');
if ($content) {
  $content.textContent = text;
}

// Add the icon
const myIcon = new Image();
myIcon.src = Icon;
document.body.appendChild(myIcon);

/////////////////////////////////////////////////////////////////////
async function run() {
  try {
    const password = utf8ToBytes("my password is easy to crack. Don't use this!");
    const wallet = await QuantumPurse.getInstance();
    await wallet.init(password); // gen and ecrypt master seed
    await wallet.genAccount(password); // gen and encrypt a child key

    const address = (await wallet).getAddress();
    console.log("address: ", address)

    // get accounts list
    const accountList = await wallet.getAllAccounts();
    console.log("account_list: ", accountList);

    // set account pointer to account 5
    wallet.setAccPointer(accountList[5])
    const newAddress = (await wallet).getAddress();
    console.log("new_address: ", newAddress)

  } catch (error) {
    console.error("Failed to initialize WASM module or execute code:", error);
  }
}

run();
/////////////////////////////////////////////////////////////////////
```