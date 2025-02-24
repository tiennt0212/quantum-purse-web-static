import { execSync } from "child_process";
import { transfer } from "../core/transaction_builder";
import QuantumPurse from "../core/quantum_purse";
import { sendTransaction } from "../core/utils";
import { utf8ToBytes } from "@noble/hashes/utils";

const CKB_INDEXER_URL = "http://localhost:8114/indexer";
const NODE_URL = "http://localhost:8114";

const testAccount = {
  "account": "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqwgx292hnvmn68xf779vmzrshpmm6epn4c0cgwga",
  "priv_key": "0xd00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc",
  "lock_arg": "0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7",
  "receiver": "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq28phxutezqvjgfv5q38gn5kwek4m9km3cmajeqs",
};

describe("Integration Test for Quantum Purse", () => {
  let wallet: QuantumPurse;
  let QPAddress: string;
  const password = utf8ToBytes("my passwork is weak, don't try this");
  const seed = QuantumPurse.generateSeedPhrase();
  const seedByte = utf8ToBytes(seed);

  beforeAll(async () => {
    wallet = QuantumPurse.getInstance();
    const encryptedSeed = await wallet.encrypt(password, seedByte);
    wallet.dbSetMasterKey(encryptedSeed);
    wallet.deriveChildKey(password);
    QPAddress = wallet.getAddress();
    console.log(">>>QPAddress: ", QPAddress);

    console.log("[INFO] Building QR lock script...");
    execSync("make build", { cwd: "rust-quantum-resistant-lock-script", stdio: "inherit" });

    console.log("[INFO] Starting CKB node...");
    execSync("bash src/test/start_ckb_node.sh", { stdio: "inherit" });

    console.log("[INFO] Loading up CKB for test account...");
    const loadingUpTxHash = execSync(`bash src/test/load_up_test_account.sh ${QPAddress} 2>&1`, {
      encoding: "utf-8",
      stdio: ["inherit", "pipe", "pipe"],
    }).trim();

    console.log("[INFO] Deploying QR lock script...");
    const deployedTxHash = execSync("bash src/test/deploy_qr_lock_script.sh 2>&1", {
      encoding: "utf-8",
      stdio: ["inherit", "pipe", "pipe"],
    }).trim();
  });

  test("Pass - Unlocking a sphincs+ protected cell", async () => {
    let tx = await transfer(QPAddress, testAccount.account, "200");
    const signedTx = await wallet.sign(tx, password);
    await sendTransaction(NODE_URL, signedTx);
  });

  afterAll(() => {
    console.log("[INFO] Terminating CKB test node...");
    execSync("docker kill ckb-test-node >/dev/null 2>&1 || true", { stdio: "inherit" });
    execSync("docker rm ckb-test-node >/dev/null 2>&1 || true", { stdio: "inherit" });
  });
});