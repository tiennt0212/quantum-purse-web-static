import {
  CKB_INDEXER_URL,
  NODE_URL,
  IS_MAIN_NET,
  SPHINCSPLUS_LOCK,
} from "./config";
import {
  hexToInt,
  insertWitnessPlaceHolder,
  prepareSphincsPlusSigningEntries,
  hexStringToUint8Array,
  uint8ArrayToHexString,
} from "./utils";
import { Reader } from "ckb-js-toolkit";
import { scriptToAddress } from "@nervosnetwork/ckb-sdk-utils";
import { CellCollector, Indexer } from "@ckb-lumos/ckb-indexer";
import { Script, HashType, utils, Transaction } from "@ckb-lumos/base";
import { CKBIndexerQueryOptions } from "@ckb-lumos/ckb-indexer/src/type";
import { TransactionSkeletonType, sealTransaction } from "@ckb-lumos/helpers";
import * as bip39 from "@scure/bip39";
import { scryptAsync } from "@noble/hashes/scrypt";
import { wordlist } from "@scure/bip39/wordlists/english";
import { slh_dsa_shake_128f } from "@noble/post-quantum/slh-dsa";

const { ckbHash } = utils;

interface EncryptionPacket {
  salt: string;
  iv: string;
  cipherText: string;
}
interface PublicSphincs {
  sphincsPlusPubKey: string;
  packet: EncryptionPacket;
}
type DBKey =
  | typeof QuantumPurse.DB_MASTER_KEY
  | typeof QuantumPurse.DB_CHILD_KEYS;

/**
 * QuantumPurse class provides functionalities for managing a wallet using
 * the SPHINCS+ post-quantum signature scheme. It ensures that only one instance
 * of the wallet is active during its uptime. By this wallet it is targeting
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

  private signer?: PublicSphincs;

  // SPHINCS+ lock script details
  public sphincsLock: { codeHash: string; hashType: HashType };

  private SALT_LENGTH = 16; // 128-bit salt
  private SCRYPT_PARAMS_FOR_SEED = { N: 2 ** 16, r: 8, p: 1, dkLen: 32 };
  private SCRYPT_PARAMS_FOR_KDF = { N: 2 ** 16, r: 8, p: 1, dkLen: 48 };
  private IV_LENGTH = 12; // 96-bit IV for AES-GCM

  public static DB_MASTER_KEY = "masterKey";
  public static DB_CHILD_KEYS = "childKeys";

  /**
   * Private constructor to enforce singleton pattern.
   * @param devKey - Development key for initial setup. TODO Should be replaced with secure key generation in production.
   * @param sphincsCodeHash - The code hash for the SPHINCS+ lock script.
   * @param sphincsHashType - The hash type for the SPHINCS+ lock script.
   */
  private constructor(sphincsCodeHash: string, sphincsHashType: HashType) {
    this.indexer = new Indexer(CKB_INDEXER_URL, NODE_URL);
    this.sphincsLock = { codeHash: sphincsCodeHash, hashType: sphincsHashType };
  }

  /**
   * Singleton method to get or create the instance of QuantumPurse.
   * @returns The singleton instance of QuantumPurse.
   */
  public static getInstance(): QuantumPurse {
    if (!QuantumPurse.instance) {
      QuantumPurse.instance = new QuantumPurse(
        SPHINCSPLUS_LOCK.codeHash,
        SPHINCSPLUS_LOCK.hashType as HashType
      );
    }
    return QuantumPurse.instance;
  }

  /**
   * Generates the lock script for this wallet instance.
   * @returns The lock script object.
   */
  private getLockScript(): Script | undefined {
    if (!this.signer) {
      throw new Error("Signer not available");
    }
    return {
      codeHash: this.sphincsLock.codeHash,
      hashType: this.sphincsLock.hashType,
      args: ckbHash(this.signer.sphincsPlusPubKey),
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
  public async sign(
    tx: TransactionSkeletonType,
    password: Uint8Array
  ): Promise<Transaction> {
    if (!this.signer) {
      throw new Error("No signer found");
    }

    let witnessLen =
      QuantumPurse.SHAKE_128F_SIMPLE_SIG_LEN +
      this.signer.sphincsPlusPubKey.length;
    tx = insertWitnessPlaceHolder(tx, witnessLen);
    tx = prepareSphincsPlusSigningEntries(tx);

    const signingEntries = tx.get("signingEntries").toArray();
    const privatekey = await this.decrypt(password, this.signer.packet);
    if (!privatekey) {
      throw new Error("Failed to decrypt private key");
    }
    const signature = slh_dsa_shake_128f.sign(
      privatekey,
      hexStringToUint8Array(signingEntries[0].message),
      this.genNonce()
    );
    privatekey.fill(0); // zero fill

    const serializedSignature = new Reader(signature.buffer).serializeJson();
    const serializedPublicKey = new Reader(
      hexStringToUint8Array(this.signer.sphincsPlusPubKey).buffer
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
    const lock = this.getLockScript();
    if (!lock) {
      throw new Error("No lock script found");
    }
    return scriptToAddress(lock, IS_MAIN_NET);
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

  /**
   * Generate a new 24 word seed phrase for max 256bit security.
   * @returns seed phrase object
   */
  public static generateSeedPhrase(): string {
    return bip39.generateMnemonic(wordlist, 256);
  }

  /**
   * This function Encrypts input data with AES-GCM.
   * At this point, validation for a strong password MUST be done beforehand.
   * @param password - The password used to encrypt the input data.
   * @param input - The data to be encrypted.
   * @returns an object type of EncryptionPacket
   */
  public async encrypt(
    password: Uint8Array,
    input: Uint8Array
  ): Promise<EncryptionPacket> {
    // Generate salt, iv
    const salt = new Uint8Array(this.SALT_LENGTH);
    const iv = new Uint8Array(this.IV_LENGTH);
    globalThis.crypto.getRandomValues(salt);
    globalThis.crypto.getRandomValues(iv);

    // Derive scrypt key
    const key = await scryptAsync(password, salt, this.SCRYPT_PARAMS_FOR_SEED);

    // zero fill
    password.fill(0);

    // Import key for AES-GCM encryption
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      "raw",
      key,
      { name: "AES-GCM" },
      false,
      ["encrypt"]
    );

    // Encrypt the input
    const encryptedData = await globalThis.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      cryptoKey,
      input
    );

    // zero fill
    input.fill(0);

    // build store packet
    return {
      salt: uint8ArrayToHexString(salt),
      iv: uint8ArrayToHexString(iv),
      cipherText: uint8ArrayToHexString(new Uint8Array(encryptedData)),
    };
  }

  /**
   * Decrypts the encrypted data using AES-GCM.
   * @param password - The user's password in Uint8Array format.
   * @param packet - The encrypted data packet.
   * @returns {Promise<Uint8Array | null>} - The decrypted data.
   * @throws {Error} - If decryption fails due to incorrect password or corrupted data.
   */
  public async decrypt(
    password: Uint8Array,
    packet: EncryptionPacket
  ): Promise<Uint8Array | null> {
    const salt = hexStringToUint8Array(packet.salt);
    const iv = hexStringToUint8Array(packet.iv);
    const cipherText = hexStringToUint8Array(packet.cipherText);

    // Derive the scrypt key
    const key = await scryptAsync(password, salt, this.SCRYPT_PARAMS_FOR_SEED);

    // Import key for decryption
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      "raw",
      key,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    //TODO check
    try {
      // Decrypt the cipherText
      const decryptedData = await globalThis.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        cryptoKey,
        cipherText
      );

      // Zero out the sensitive data
      password.fill(0);

      return new Uint8Array(decryptedData);
    } catch (error) {
      console.error("Decryption failed:", error);
      //TODO check null/undefined
      return null;
    }
  }

  /**
   * Cleans the localStorage.
   * @returns void
   */
  public dbClear(dbKey: DBKey): void {
    // localStorage.clear();
    localStorage.removeItem(dbKey);
  }

  /**
   * Overwrite the encrypted masterseed in local storage.
   * @param input - The encrypted input data.
   * @returns none
   * TODO add warning
   */
  public dbSetMaster(input: EncryptionPacket) {
    localStorage.setItem(QuantumPurse.DB_MASTER_KEY, JSON.stringify(input));
  }

  /**
   * Overwrite the encrypted masterseed in local storage.
   * @param input - The encrypted input data.
   * @returns none
   * TODO add warning
   */
  public dbGetMaster(): EncryptionPacket | undefined {
    const localData = localStorage.getItem(QuantumPurse.DB_MASTER_KEY);
    if (!localData) {
      return undefined;
    }
    return JSON.parse(localData);
  }

  /**
   * Store the encrypted data in local storage.
   * @param input - The encrypted input data.
   * @returns none
   */
  public dbSetChild(input: PublicSphincs) {
    const dbKey = QuantumPurse.DB_CHILD_KEYS;
    const localData = localStorage.getItem(dbKey);
    let packets: PublicSphincs[] = localData ? JSON.parse(localData) : [];

    // Check if the sphincsPlusPubKey already exists in the stored packets
    const keyExists = packets.some(
      (packet) => packet.sphincsPlusPubKey === input.sphincsPlusPubKey
    );

    // If the key already exists, return
    if (keyExists) {
      return;
    }

    // Append the new store structure
    packets.push(input);

    // Store locally
    localStorage.setItem(dbKey, JSON.stringify(packets));
  }

  /**
   * Retrieve encrypted data from local storage.
   * @param key - Optional sphincsPlusPubKey to retrieve a single PublicSphincs object.
   * @returns A single PublicSphincs object (or undefined) if key is specified.
   */
  public dbGetChild(key: string): PublicSphincs[] | PublicSphincs | undefined {
    const dbKey = QuantumPurse.DB_CHILD_KEYS;
    try {
      const localData = localStorage.getItem(dbKey);
      if (!localData) {
        return key ? undefined : [];
      }

      const packets: PublicSphincs[] = JSON.parse(localData);

      if (key) {
        return packets.find((packet) => packet.sphincsPlusPubKey === key);
      }

      return packets;
    } catch (error) {
      console.error(`Failed to retrieve data for key ${dbKey}:`, error);
      return key ? undefined : [];
    }
  }

  /**
   * Retrieve all encrypted account data from local storage.
   * @returns An array of PublicSphincs objects if no key is provided,
   * or a single PublicSphincs object (or undefined) if key is specified.
   */
  public dbGetChilds(): PublicSphincs[] | PublicSphincs | undefined {
    const dbKey = QuantumPurse.DB_CHILD_KEYS;
    try {
      const localData = localStorage.getItem(dbKey);
      if (!localData) {
        return [];
      }

      const packets: PublicSphincs[] = JSON.parse(localData);

      return packets;
    } catch (error) {
      console.error(`Failed to retrieve data for key ${dbKey}:`, error);
      return [];
    }
  }

  /**
   * Create a new account derived from the wallet's seed phrase
   * The derivation path is in the format of pq/ckb/{index}.
   * @returns Account object
   */
  public async createAccount(password: Uint8Array) {
    const localData = this.dbGetChilds() as PublicSphincs[];

    console.log(">>>localData: ", localData);
    const path = `pq/ckb/${localData.length}`;
    console.log(">>>mark1 | localData: ", localData);
    console.log(">>>mark3 | path: ", path);

    // load up seed and decrypt
    const encryptedSeedObj = this.dbGetMaster();

    if (!encryptedSeedObj) {
      throw new Error("Master seed not found");
    }

    const seed = await this.decrypt(password, encryptedSeedObj);

    if (!seed) throw new Error("Seed decryption failed");

    // Derive 48-byte key using scrypt for sphincs+ key gen.
    // Here we're using path as salt to achieve determinism
    const sphincsSeed = await scryptAsync(
      seed,
      path,
      this.SCRYPT_PARAMS_FOR_KDF
    );

    const sphincsPlusKey = slh_dsa_shake_128f.keygen(sphincsSeed);
    sphincsPlusKey.secretKey.fill(0);
    console.log(">>>sphincsPlusKey: ", sphincsPlusKey);

    // encrypt key and store
    const encryptedChild = await this.encrypt(password, sphincsSeed);
    const currentAccount = {
      sphincsPlusPubKey: uint8ArrayToHexString(sphincsPlusKey.publicKey),
      packet: encryptedChild,
    };
    this.dbSetChild(currentAccount);
    // init current account
    this.signer = currentAccount;

    // Zero out the sensitive data
    password.fill(0);
    seed.fill(0);
    sphincsSeed.fill(0);
  }

  /**
   * Import a wallet using a provided seed phrase
   * @param seedPhrase - The seed phrase
   * @returns Imported wallet ID
   */
  public importSeedPhrase(seedPhrase: string) {}

  /**
   * Export a wallet's seed phrase
   * @param walletId - The wallet ID
   * @returns Seed phrase
   */
  public exportSeedPhrase(walletId: string) {}
}

export default QuantumPurse;
