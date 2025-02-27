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

interface SphincsPlusSigner {
  sphincsPlusPubKey: string;
  sphincsPlusPriEnc: EncryptionPacket;
}

/**
 * Manages a wallet using the SPHINCS+ post-quantum signature scheme (shake-128f simple).
 * Implements a singleton pattern to ensure a single instance during runtime.
 */
class QuantumPurse {
  static readonly SPX_SIG_LEN: number = 17088; // SPHINCS+ signature length
  static readonly STORE_MASTER_KEY = "masterKey";
  static readonly STORE_CHILD_KEYS = "childKeys";

  private SALT_LENGTH = 16; // 128-bit salt
  private IV_LENGTH = 12; // 96-bit IV for AES-GCM
  private SCRYPT_PARAMS_FOR_AES_KEY = { N: 2 ** 16, r: 8, p: 1, dkLen: 32 }; // to gen AES maximum 256 bits long key
  private SCRYPT_PARAMS_FOR_SPX_KEY = { N: 2 ** 16, r: 8, p: 1, dkLen: 48 }; // sphincs+ key gen requires 48-byte seed
  private DB: Promise<IDBDatabase> | null = null; // indexed db inferface
  private currentSigner?: SphincsPlusSigner;
  private static instance: QuantumPurse | null = null; // Singleton instance

  public sphincsLock: { codeHash: string; hashType: HashType }; // SPHINCS+ lock script

  /** Constructor that takes sphincs+ on-chain binary deployment info */
  private constructor(sphincsCodeHash: string, sphincsHashType: HashType) {
    this.sphincsLock = { codeHash: sphincsCodeHash, hashType: sphincsHashType };
  }

  /** Returns the singleton instance of QuantumPurse. */
  public static getInstance(): QuantumPurse {
    if (!QuantumPurse.instance) {
      QuantumPurse.instance = new QuantumPurse(
        SPHINCSPLUS_LOCK.codeHash,
        SPHINCSPLUS_LOCK.hashType as HashType
      );
    }
    return QuantumPurse.instance;
  }

  private async getDB(): Promise<IDBDatabase> {
    if (this.DB) {
      return this.DB;
    }
    this.DB = new Promise((resolve, reject) => {
      const request = indexedDB.open("QuantumPurseDB", 1);
      request.onupgradeneeded = (event) => {
        const db = request.result;
        if (!db.objectStoreNames.contains(QuantumPurse.STORE_MASTER_KEY)) {
          db.createObjectStore(QuantumPurse.STORE_MASTER_KEY);
        }
        if (!db.objectStoreNames.contains(QuantumPurse.STORE_CHILD_KEYS)) {
          db.createObjectStore(QuantumPurse.STORE_CHILD_KEYS, { keyPath: "sphincsPlusPubKey" });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    return this.DB;
  }

  /** Generates the lock script for the current signer. */
  private getLockScript(): Script {
    if (!this.currentSigner) throw new Error("Signer not available!");
    return {
      codeHash: this.sphincsLock.codeHash,
      hashType: this.sphincsLock.hashType,
      args: ckbHash(this.currentSigner.sphincsPlusPubKey),
    };
  }

  /** Returns the blockchain address for the current signer. */
  public getAddress(): string {
    const lock = this.getLockScript();
    return scriptToAddress(lock, IS_MAIN_NET);
  }

  /** Generates a random nonce for SPHINCS+ signing. */
  private genNonce(): Uint8Array {
    const nonce = new Uint8Array(slh_dsa_shake_128f.signRandBytes);
    globalThis.crypto.getRandomValues(nonce);
    return nonce;
  }

  /**
   * Calculates the wallet's balance from the blockchain.
   * @returns Balance in BigInt.
   */
  public async getBalance(): Promise<BigInt> {
    const query: CKBIndexerQueryOptions = {
      lock: this.getLockScript(),
      type: "empty",
    };
    const cellCollector = new CellCollector(
      new Indexer(CKB_INDEXER_URL, NODE_URL),
      query
    );
    let balance = BigInt(0);

    for await (const cell of cellCollector.collect()) {
      balance += hexToInt(cell.cellOutput.capacity);
    }
    return balance;
  }

  /**
   * Signs a transaction using SPHINCS+.
   * @param tx - Transaction skeleton to sign.
   * @param password - Password to decrypt the private key to sign the message.
   * @returns Signed transaction.
   */
  public async sign(
    tx: TransactionSkeletonType,
    password: Uint8Array
  ): Promise<Transaction> {
    if (!this.currentSigner) throw new Error("Signer not available!");

    const witnessLen =
      QuantumPurse.SPX_SIG_LEN + hexStringToUint8Array(this.currentSigner.sphincsPlusPubKey).length;
    tx = insertWitnessPlaceHolder(tx, witnessLen);
    tx = prepareSphincsPlusSigningEntries(tx);

    const signingEntries = tx.get("signingEntries").toArray();
    const privateKey = await this.decrypt(password, this.currentSigner.sphincsPlusPriEnc);
    if (!privateKey) throw new Error("Failed to decrypt private key");

    const signature = slh_dsa_shake_128f.sign(
      privateKey,
      hexStringToUint8Array(signingEntries[0].message),
      this.genNonce()
    );
    privateKey.fill(0); // Clear sensitive data

    const serializedSignature = new Reader(signature.buffer).serializeJson();

    const witness =
      serializedSignature + this.currentSigner.sphincsPlusPubKey.replace(/^0x/, "");
    return sealTransaction(tx, [witness]);
  }

  /** Generates a 24-word seed phrase with 256-bit security. */
  public static generateSeedPhrase(): string {
    return bip39.generateMnemonic(wordlist, 256);
  }

  /**
   * Encrypts data with AES-GCM.
   * @param password - Password for encryption.
   * @param input - Data to encrypt.
   * @returns Encrypted data packet.
   */
  public async encrypt(
    password: Uint8Array,
    input: Uint8Array
  ): Promise<EncryptionPacket> {
    const salt = new Uint8Array(this.SALT_LENGTH);
    const iv = new Uint8Array(this.IV_LENGTH);
    globalThis.crypto.getRandomValues(salt);
    globalThis.crypto.getRandomValues(iv);

    const key = await scryptAsync(password, salt, this.SCRYPT_PARAMS_FOR_AES_KEY);
    password.fill(0); // Clear sensitive data

    const cryptoKey = await globalThis.crypto.subtle.importKey(
      "raw",
      key,
      { name: "AES-GCM" },
      false,
      ["encrypt"]
    );

    const encryptedData = await globalThis.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      cryptoKey,
      input
    );
    input.fill(0); // Clear sensitive data

    return {
      salt: uint8ArrayToHexString(salt),
      iv: uint8ArrayToHexString(iv),
      cipherText: uint8ArrayToHexString(new Uint8Array(encryptedData)),
    };
  }

  /**
   * Decrypts data using AES-GCM.
   * @param password - Password for decryption.
   * @param packet - Encrypted data packet.
   * @returns Decrypted data or null if decryption fails.
   */
  public async decrypt(
    password: Uint8Array,
    packet: EncryptionPacket
  ): Promise<Uint8Array | null> {
    const salt = hexStringToUint8Array(packet.salt);
    const iv = hexStringToUint8Array(packet.iv);
    const cipherText = hexStringToUint8Array(packet.cipherText);

    const key = await scryptAsync(password, salt, this.SCRYPT_PARAMS_FOR_AES_KEY);
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      "raw",
      key,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    try {
      const decryptedData = await globalThis.crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        cryptoKey,
        cipherText
      );
      password.fill(0); // Clear sensitive data
      return new Uint8Array(decryptedData);
    } catch (error) {
      console.error("Decryption failed:", error);
      return null;
    }
  }

  /**
   * Clears a specific object store in IndexedDB.
   */
  public async dbClear(dbKey: typeof QuantumPurse.STORE_MASTER_KEY | typeof QuantumPurse.STORE_CHILD_KEYS): Promise<void> {
    const db = await this.getDB();
    const tx = db.transaction(dbKey, "readwrite");
    const store = tx.objectStore(dbKey);
    const request = store.clear();
    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Stores encrypted master key (seed) in IndexedDB.
   * @warning Overwrites existing data in IndexedDB.
   */
  public async dbSetMasterKey(input: EncryptionPacket): Promise<void> {
    const db = await this.getDB();
    const tx = db.transaction(QuantumPurse.STORE_MASTER_KEY, "readwrite");
    const store = tx.objectStore(QuantumPurse.STORE_MASTER_KEY);
    const request = store.put(input, "masterKeyEntry");
    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  /** Retrieves encrypted master key (seed) from IndexedDB. */
  public async dbGetMasterKey(): Promise<EncryptionPacket | null> {
    const db = await this.getDB();
    const tx = db.transaction(QuantumPurse.STORE_MASTER_KEY, "readonly");
    const store = tx.objectStore(QuantumPurse.STORE_MASTER_KEY);
    const request = store.get("masterKeyEntry");
    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
    });
  }

  /** Stores encrypted child key data in IndexedDB. */
  public async dbSetChildKey(input: SphincsPlusSigner): Promise<void> {
    const db = await this.getDB();
    const tx = db.transaction(QuantumPurse.STORE_CHILD_KEYS, "readwrite");
    const store = tx.objectStore(QuantumPurse.STORE_CHILD_KEYS);
    const existing = await new Promise((resolve, reject) => {
      const request = store.get(input.sphincsPlusPubKey);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    if (!existing) {
      const request = store.put(input);
      await new Promise<void>((resolve, reject) => {
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
    }
  }

  /**
   * Retrieves a SphincsPlusSigner object from IndexedDB using a SPHINCS+ public key.
   * @param key - The SPHINCS+ public key to look up in DB.
   * @returns The matching SphincsPlusSigner object, or null.
   */
  public async dbGetChildKey(key: string): Promise<SphincsPlusSigner | null> {
    const db = await this.getDB();
    const tx = db.transaction(QuantumPurse.STORE_CHILD_KEYS, "readonly");
    const store = tx.objectStore(QuantumPurse.STORE_CHILD_KEYS);
    const request = store.get(key);
    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
    });
  }

  /** Retrieves all child key data from IndexedDB. */
  public async dbGetChildKeys(): Promise<SphincsPlusSigner[]> {
    const db = await this.getDB();
    const tx = db.transaction(QuantumPurse.STORE_CHILD_KEYS, "readonly");
    const store = tx.objectStore(QuantumPurse.STORE_CHILD_KEYS);
    const request = store.getAll();
    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Creates a new account derived from the master key (seed).
   * @param password - Password to decrypt the encrypted master key (seed) and encrypt the child key.
   */
  public async deriveChildKey(password: Uint8Array): Promise<void> {
    // Because decrypt by default will zero out the password, we need to clone the password.
    // Although this can be redesigned to let user decrypt master seed then derive keys,
    // it's more secure to do it in side this function automatically then dispose the password.
    const passwordClone = new Uint8Array(password);
    const childKeys = await this.dbGetChildKeys();
    const path = `pq/ckb/${childKeys.length}`;

    const packet = await this.dbGetMasterKey();
    if (!packet) throw new Error("Master key (seed) not found!");

    const seed = await this.decrypt(password, packet);
    if (!seed)
      throw new Error("Seed decryption failed!");

    const sphincsSeed = await scryptAsync(
      seed,
      path,
      this.SCRYPT_PARAMS_FOR_SPX_KEY
    );
    const sphincsPlusKey = slh_dsa_shake_128f.keygen(sphincsSeed);

    const encryptedChild = await this.encrypt(passwordClone, sphincsPlusKey.secretKey);
    const currentAccount: SphincsPlusSigner = {
      sphincsPlusPubKey: uint8ArrayToHexString(sphincsPlusKey.publicKey),
      sphincsPlusPriEnc: encryptedChild,
    };

    await this.dbSetChildKey(currentAccount);
    this.currentSigner = currentAccount;

    // Clear sensitive data
    password.fill(0);
    passwordClone.fill(0);
    seed.fill(0);
    sphincsSeed.fill(0);
    sphincsPlusKey.secretKey.fill(0);
  }

  /** Sets the current signer for SPHINCS+ operations. */
  public setSigner(signer: SphincsPlusSigner): void {
    this.currentSigner = signer;
  }
  /**
   * Calculates the entropy of a password in bits, aligned with antivirus.promo behavior.
   * Processes the raw Uint8Array directly and overwrites it with fill(0) after use.
   * @param password - The password as a Uint8Array (UTF-8 encoded), will be zeroed out after processing.
   * @returns The entropy in bits (e.g., 1, 2, 128, 256, 444, etc.), or 0 for invalid/empty input.
   */
  public static calculatePasswordEntropy(password: Uint8Array): number {
    // Validate input
    if (!password || password.length === 0) {
      return 0;
    }

    const length = password.length; // Use byte length

    // Estimate pool size based on ASCII character categories
    let hasLower = false,
      hasUpper = false,
      hasDigit = false,
      hasSymbol = false,
      hasNonAscii = false;
    for (let i = 0; i < length; i++) {
      const byte = password[i];
      if (byte >= 97 && byte <= 122) hasLower = true; // a-z
      else if (byte >= 65 && byte <= 90) hasUpper = true; // A-Z
      else if (byte >= 48 && byte <= 57) hasDigit = true; // 0-9
      else if (
        (byte >= 33 && byte <= 47) ||
        (byte >= 58 && byte <= 64) ||
        (byte >= 91 && byte <= 96) ||
        (byte >= 123 && byte <= 126)
      )
        hasSymbol = true; // !-/ : @-` {~}
      else if (byte > 127) hasNonAscii = true; // UTF-8 multi-byte
    }

    // Determine pool size based on detected categories
    let poolSize = 0;
    if (hasLower) poolSize += 26; // Lowercase
    if (hasUpper) poolSize += 26; // Uppercase
    if (hasDigit) poolSize += 10; // Digits
    if (hasSymbol) poolSize += 32; // Symbols

    // Handle edge cases and non-ASCII
    if (poolSize === 0) {
      poolSize = 1; // Minimum pool for all-same or uncategorized bytes (e.g., "aaa")
    }
    if (hasNonAscii) {
      poolSize = Math.max(poolSize, 94); // Minimum for full printable ASCII
      poolSize = Math.min(poolSize, 256); // Cap at byte max for UTF-8
    }

    // Entropy = length * log2(poolSize), rounded down
    const entropy = Math.floor(length * Math.log2(poolSize));

    // Overwrite the input password
    password.fill(0);

    return entropy;
  }

  /**
   * Imports a wallet using a seed phrase.
   * @param seedPhrase - Seed phrase to import.
   * @warning Overwrite current seed phrase in DB.
   */
  public async importSeedPhrase(seedPhrase: Uint8Array, password: Uint8Array): Promise<void> {
    const packet = await this.encrypt(password, seedPhrase);
    await this.dbSetMasterKey(packet);
    seedPhrase.fill(0);
    password.fill(0);
  }

  /**
   * Exports a wallet's seed phrase.
   * @param walletId - Wallet ID to export.
   * @returns The seed phrase as a Uint8Array.
   * @warning To avoid leakage, handle the ouput carefully.
   */
  public async exportSeedPhrase(password: Uint8Array): Promise<Uint8Array> {
    const packet = await this.dbGetMasterKey();
    if (!packet) throw new Error("Master key (seed) not found!");
    const seed = await this.decrypt(password, packet);
    if (!seed) throw new Error("Master key (seed) decryption failed!");
    password.fill(0);
    return seed;
  }
}

export default QuantumPurse;