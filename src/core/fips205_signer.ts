import { DEV_KEY, SPHINCSPLUS_LOCK } from "./config_wallet";
import { Script, HashType, utils, Transaction } from "@ckb-lumos/base";
const { ckbHash } = utils;
import { slh_dsa_shake_128f } from "@noble/post-quantum/slh-dsa";
import { TransactionSkeletonType, sealTransaction } from "@ckb-lumos/helpers";
import { Reader } from "ckb-js-toolkit";
import {
  hexToInt,
  insertWitnessPlaceHolder,
  prepareSphincsPlusSigningEntries,
  hexStringToUint8Array,
} from "./utils";
import { scriptToAddress } from "@nervosnetwork/ckb-sdk-utils";
import { CKBIndexerQueryOptions } from "@ckb-lumos/ckb-indexer/src/type";
import { CellCollector, Indexer } from "@ckb-lumos/ckb-indexer";
import { CKB_INDEXER_URL, NODE_URL, IS_MAIN_NET } from "./config_wallet";

type Key = { pubkey: Uint8Array; prikey: Uint8Array };

/**
 * QuantumPurse class provides functionalities for managing a wallet using the SPHINCS+ post-quantum signature scheme.
 * It ensures that only one instance of the wallet is active during its uptime. By this wallet it is targeting
 * shake-128f simple algorithm configuration
 */
class QuantumPurse {
  // Length of the SPHINCS+ signature
  static readonly SHAKE_128F_SIMPLE_SIG_LEN: number = 17088;

  // Length of the message digest(256 bit) used in cryptographic operations
  static readonly MESSAGE_LEN: number = 32;

  // Length of the entropy used for Sphincs+ key generation
  static readonly ENTROPY_LEN: number = 48;

  // Singleton instance of QuantumPurse to ensure only one instance is created
  private static instance: QuantumPurse | null = null;

  // Indexer for blockchain interactions
  private indexer: Indexer;

  // Private key for Sphincs+ signing operations
  private privateKey: Uint8Array;

  // Public key for Sphincs+ verification purposes
  public publicKey: Uint8Array;

  // SPHINCS+ lock script details
  public sphincsLock: { codeHash: string; hashType: HashType };

  /**
   * Private constructor to enforce singleton pattern.
   * @param devKey - Development key for initial setup. TODO Should be replaced with secure key generation in production.
   * @param sphincsCodeHash - The code hash for the SPHINCS+ lock script.
   * @param sphincsHashType - The hash type for the SPHINCS+ lock script.
   */
  private constructor(
    devKey: Key,
    sphincsCodeHash: string,
    sphincsHashType: HashType
  ) {
    this.indexer = new Indexer(CKB_INDEXER_URL, NODE_URL);
    this.privateKey = devKey.prikey;
    this.publicKey = devKey.pubkey;
    this.sphincsLock = { codeHash: sphincsCodeHash, hashType: sphincsHashType };
  }

  /**
   * Singleton method to get or create the instance of QuantumPurse.
   * @returns The singleton instance of QuantumPurse.
   */
  public static getInstance(): QuantumPurse {
    if (!QuantumPurse.instance) {
      QuantumPurse.instance = new QuantumPurse(
        DEV_KEY,
        SPHINCSPLUS_LOCK.codeHash,
        SPHINCSPLUS_LOCK.hashType as HashType
      );
    }
    return QuantumPurse.instance;
  }

  /**
   * Generates a new key pair for the wallet. TODO to replace DEV_KEY.
   */
  private generateKey() {
    // Be sure to use a secure random number generator
    const seed = new Uint8Array(QuantumPurse.ENTROPY_LEN);
    globalThis.crypto.getRandomValues(seed);
    const keys = slh_dsa_shake_128f.keygen(seed);
    this.publicKey = keys.publicKey;
    this.privateKey = keys.secretKey;
  }

  /**
   * Generates the lock script for this wallet instance.
   * @returns The lock script object.
   */
  private getLockScript(): Script {
    return {
      codeHash: this.sphincsLock.codeHash,
      hashType: this.sphincsLock.hashType,
      args: ckbHash(this.publicKey),
    };
  }

  /**
   * Generates a nonce for cryptographic operations.
   * @returns A Uint8Array representing the nonce.
   */
  private genNonce(): Uint8Array {
    const nonce = new Uint8Array(slh_dsa_shake_128f.signRandBytes);
    globalThis.crypto.getRandomValues(nonce);
    return nonce;
  }

  /**
   * Signs a transaction using the SPHINCS+ algorithm.
   * @param tx - The transaction skeleton to sign.
   * @returns The sealed transaction with signatures.
   */
  public sign(tx: TransactionSkeletonType): Transaction {
    let witnessLen =
      QuantumPurse.SHAKE_128F_SIMPLE_SIG_LEN + this.publicKey.length;
    tx = insertWitnessPlaceHolder(tx, witnessLen);
    tx = prepareSphincsPlusSigningEntries(tx);

    const signingEntries = tx.get("signingEntries").toArray();
    const signature = slh_dsa_shake_128f.sign(
      this.privateKey,
      hexStringToUint8Array(signingEntries[0].message),
      this.genNonce()
    );

    const serializedSignature = new Reader(signature.buffer).serializeJson();
    const serializedPublicKey = new Reader(
      this.publicKey.buffer
    ).serializeJson();

    const witness =
      serializedSignature + serializedPublicKey.replace(/^0x/, "");

    return sealTransaction(tx, [witness]);
  }

  /**
   * Retrieves the blockchain address associated with this wallet.
   * @returns The address as a string.
   */
  public getAddress(): string {
    return scriptToAddress(this.getLockScript(), IS_MAIN_NET);
  }

  /**
   * Fetches and calculates the current balance of this wallet from the blockchain.
   * @returns A promise that resolves to the balance in BigInt.
   */
  public async getBalance(): Promise<BigInt> {
    const query: CKBIndexerQueryOptions = {
      lock: this.getLockScript(),
      type: "empty",
    };

    const cellCollector = new CellCollector(this.indexer, query);
    let balance = BigInt(0);

    for await (const cell of cellCollector.collect()) {
      balance += hexToInt(cell.cellOutput.capacity);
    }

    return balance;
  }
}

export default QuantumPurse;
