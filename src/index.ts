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