
import { execSync } from "child_process";
import { transfer } from "../core/transaction_builder";

import QuantumPurse from "../core/fips205_signer";
import { sendTransaction } from "../core/utils";
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

  beforeAll(() => {
    wallet = QuantumPurse.getInstance();
    QPAddress = wallet.getAddress();

    console.log("👉 Building QR locks cript...");
    execSync("make build", { cwd: "rust-quantum-resistant-lock-script", stdio: "inherit" });

    console.log("👉 Starting CKB node...");
    execSync("bash src/__tests__/start_ckb_node.sh", { stdio: "inherit" });

    console.log("👉 Loading up CKB for test account...");
    const loadingUpTxHash = execSync(`bash src/__tests__/load_up_test_account.sh ${QPAddress} 2>&1`, {
      encoding: "utf-8",
      stdio: ["inherit", "pipe", "pipe"],
    }).trim();

    console.log("👉 Deploying QR lock script...");
    const deployedTxHash = execSync("bash src/__tests__/deploy_qr_lock_script.sh 2>&1", {
      encoding: "utf-8",
      stdio: ["inherit", "pipe", "pipe"],
    }).trim();
  });

  test("Pass - Unlocking a sphincs+ protected cell", async () => {
    
    let tx = await transfer(QPAddress, testAccount.account, "200");
    const signedTx = wallet.sign(tx);
    let txId = await sendTransaction(NODE_URL, signedTx);
    console.log("👉 Running contract tests...");
  });

  afterAll(() => {
    console.log("👉 Terminating CKB test node...");
    execSync("docker kill ckb-test-node >/dev/null 2>&1 || true", { stdio: "inherit" });
    execSync("docker rm ckb-test-node >/dev/null 2>&1 || true", { stdio: "inherit" });
  });
});
