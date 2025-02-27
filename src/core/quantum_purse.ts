// QuantumPurse.ts
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

/**
 * Represents an encrypted data packet used for storing sensitive information.
 */
export interface EncryptionPacket {
  /** Hex-encoded salt used for key derivation. */
  salt: string;
  /** Hex-encoded initialization vector (IV) for AES-GCM encryption. */
  iv: string;
  /** Hex-encoded encrypted ciphertext. */
  cipherText: string;
}

/**
 * Represents a SPHINCS+ signer with public key and encrypted private key.
 */
export interface SphincsPlusSigner {
  /** Hex-encoded SPHINCS+ public key. */
  sphincsPlusPubKey: string;
  /** Encrypted SPHINCS+ private key packet. */
  sphincsPlusPriEnc: EncryptionPacket;
}

/**
 * Manages a wallet using the SPHINCS+ post-quantum signature scheme (shake-128f simple)
 * on the Nervos CKB blockchain. Implements a singleton pattern to ensure a single instance.
 *
 * This class provides functionality for generating accounts, signing transactions,
 * managing seed phrases, and interacting with the blockchain.
 */
export default class QuantumPurse {
  static readonly SPX_SIG_LEN: number = 17088; // SPHINCS+ signature length
  static readonly STORE_MASTER_KEY = "masterKey";
  static readonly STORE_CHILD_KEYS = "childKeys";

  private SALT_LENGTH = 16; // 128-bit salt
  private IV_LENGTH = 12; // 96-bit IV for AES-GCM
  private SCRYPT_PARAMS_FOR_AES_KEY = { N: 2 ** 16, r: 8, p: 1, dkLen: 32 }; // to gen AES maximum 256 bits long key
  private SCRYPT_PARAMS_FOR_SPX_KEY = { N: 2 ** 16, r: 8, p: 1, dkLen: 48 }; // sphincs+ key gen requires 48-byte seed
  private DB: Promise<IDBDatabase> | null = null; // indexed db inferface
  private signer?: SphincsPlusSigner;
  private static instance: QuantumPurse | null = null; // Singleton instance

  public sphincsLock: { codeHash: string; hashType: HashType }; // SPHINCS+ lock script

  /** Constructor that takes sphincs+ on-chain binary deployment info */
  private constructor(sphincsCodeHash: string, sphincsHashType: HashType) {
    this.sphincsLock = { codeHash: sphincsCodeHash, hashType: sphincsHashType };
  }

  /**
   * Gets the singleton instance of QuantumPurse.
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
          db.createObjectStore(QuantumPurse.STORE_CHILD_KEYS, {
            keyPath: "sphincsPlusPubKey",
          });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    return this.DB;
  }

  /** Generates the ckb lock script for the current signer. */
  private getLock(): Script {
    if (!this.signer) throw new Error("Signer not available!");
    return {
      codeHash: this.sphincsLock.codeHash,
      hashType: this.sphincsLock.hashType,
      args: ckbHash(this.signer.sphincsPlusPubKey),
    };
  }

  /**
   * Gets the blockchain address for the current signer.
   * @returns The CKB address as a string.
   * @throws Error if no signer is set (see `getLock` for details).
   */
  public getAddress(): string {
    const lock = this.getLock();
    return scriptToAddress(lock, IS_MAIN_NET);
  }

  /** Generates a random nonce for SPHINCS+ signing. */
  private genNonce(): Uint8Array {
    const nonce = new Uint8Array(slh_dsa_shake_128f.signRandBytes);
    globalThis.crypto.getRandomValues(nonce);
    return nonce;
  }

  /**
   * Calculates the wallet's balance on the Nervos CKB blockchain.
   * @returns A promise resolving to the balance in BigInt (in shannons).
   * @throws Error if no signer is set (see `getLock` for details).
   */
  public async getBalance(): Promise<bigint> {
    const query: CKBIndexerQueryOptions = {
      lock: this.getLock(),
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
   * Signs a Nervos CKB transaction using the SPHINCS+ signature scheme.
   * @param tx - The transaction skeleton to sign.
   * @param password - The password to decrypt the private key (will be zeroed out after use).
   * @returns A promise resolving to the signed transaction.
   * @throws Error if no signer is set or decryption fails.
   * @remark The password and sensitive data are overwritten with zeros after use for security.
   */
  public async sign(
    tx: TransactionSkeletonType,
    password: Uint8Array
  ): Promise<Transaction> {
    if (!this.signer) throw new Error("Signer not available!");

    const witnessLen =
      QuantumPurse.SPX_SIG_LEN +
      hexStringToUint8Array(this.signer.sphincsPlusPubKey).length;
    tx = insertWitnessPlaceHolder(tx, witnessLen);
    tx = prepareSphincsPlusSigningEntries(tx);

    const signingEntries = tx.get("signingEntries").toArray();
    const privateKey = await this.decrypt(
      password,
      this.signer.sphincsPlusPriEnc
    ); // password is cleared already by decrypt.
    if (!privateKey) throw new Error("Failed to decrypt private key");

    const signature = slh_dsa_shake_128f.sign(
      privateKey,
      hexStringToUint8Array(signingEntries[0].message),
      this.genNonce()
    );
    privateKey.fill(0); // Clear sensitive data

    const serializedSignature = new Reader(signature.buffer).serializeJson();

    const witness =
      serializedSignature + this.signer.sphincsPlusPubKey.replace(/^0x/, "");
    return sealTransaction(tx, [witness]);
  }

  /**
   * Generates a 24-word seed phrase with 256-bit security using BIP-39.
   * @returns A mnemonic seed phrase as a string.
   */
  public static generateSeedPhrase(): string {
    return bip39.generateMnemonic(wordlist, 256);
  }

  /**
   * Encrypts data using AES-GCM with a password-derived key.
   * @param password - The password for encryption (will be zeroed out).
   * @param input - The data to encrypt as a Uint8Array (will be zeroed out).
   * @returns A promise resolving to the encrypted data packet.
   * @remark Password, input and sensitive data are are overwritten with zeros after use for security.
   */
  public async encrypt(
    password: Uint8Array,
    input: Uint8Array
  ): Promise<EncryptionPacket> {
    const salt = new Uint8Array(this.SALT_LENGTH);
    const iv = new Uint8Array(this.IV_LENGTH);
    globalThis.crypto.getRandomValues(salt);
    globalThis.crypto.getRandomValues(iv);

    const key = await scryptAsync(
      password,
      salt,
      this.SCRYPT_PARAMS_FOR_AES_KEY
    );
    password.fill(0); // Clear sensitive data

    const cryptoKey = await globalThis.crypto.subtle.importKey(
      "raw",
      key,
      { name: "AES-GCM" },
      false,
      ["encrypt"]
    );
    key.fill(0); // Clear sensitive data

    const encryptedData = await globalThis.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      cryptoKey,
      input
    ); // TODO dispose cryptoKey
    input.fill(0); // Clear sensitive data

    return {
      salt: uint8ArrayToHexString(salt),
      iv: uint8ArrayToHexString(iv),
      cipherText: uint8ArrayToHexString(new Uint8Array(encryptedData)),
    };
  }

  /**
   * Decrypts data using AES-GCM with a password-derived key.
   * @param password - The password for decryption (will be zeroed out).
   * @param packet - The encrypted data packet to decrypt.
   * @returns A promise resolving to the decrypted data as a Uint8Array, or null if decryption fails.
   * @remark The password is overwritten with zeros after use. Handle the output carefully to avoid leakage.
   */
  private async decrypt(
    password: Uint8Array,
    packet: EncryptionPacket
  ): Promise<Uint8Array | null> {
    const salt = hexStringToUint8Array(packet.salt);
    const iv = hexStringToUint8Array(packet.iv);
    const cipherText = hexStringToUint8Array(packet.cipherText);

    const key = await scryptAsync(
      password,
      salt,
      this.SCRYPT_PARAMS_FOR_AES_KEY
    );
    password.fill(0); // Clear sensitive data

    const cryptoKey = await globalThis.crypto.subtle.importKey(
      "raw",
      key,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );
    key.fill(0); // Clear sensitive data

    try {
      const decryptedData = await globalThis.crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        cryptoKey,
        cipherText
      ); // TODO dispose cryptoKey
      return new Uint8Array(decryptedData);
    } catch (error) {
      console.error("Decryption failed:", error);
      return null;
    }
  }

  /**
   * Clears all data from a specific store in IndexedDB.
   * @param dbKey - The store to clear ("masterKey" or "childKeys").
   * @returns A promise that resolves when the store is cleared.
   */
  public async dbClear(
    dbKey:
      | typeof QuantumPurse.STORE_MASTER_KEY
      | typeof QuantumPurse.STORE_CHILD_KEYS
  ): Promise<void> {
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
   * Stores a single encrypted master key (seed) in IndexedDB.
   * @warning Overwrites existing data in IndexedDB.
   */
  public async setSeed(input: EncryptionPacket): Promise<void> {
    const db = await this.getDB();
    const tx = db.transaction(QuantumPurse.STORE_MASTER_KEY, "readwrite");
    const store = tx.objectStore(QuantumPurse.STORE_MASTER_KEY);
    const request = store.put(input, "masterKeyEntry");
    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  /** Retrieves the single encrypted master key (seed) from IndexedDB. */
  private async getSeed(): Promise<EncryptionPacket | null> {
    const db = await this.getDB();
    const tx = db.transaction(QuantumPurse.STORE_MASTER_KEY, "readonly");
    const store = tx.objectStore(QuantumPurse.STORE_MASTER_KEY);
    const request = store.get("masterKeyEntry");
    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
    });
  }

  /** Stores an account object of type SphincsPlusSigner in IndexedDB. Helper for genAccount function */
  private async setAccount(input: SphincsPlusSigner): Promise<void> {
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
   * Retrieves an account from IndexedDB using the SPHINCS+ public key.
   * @param spxPubKey - The hex-encoded SPHINCS+ public key to look up.
   * @returns A promise resolving to the matching SphincsPlusSigner or null if not found.
   */
  public async getAccount(
    spxPubKey: string
  ): Promise<SphincsPlusSigner | null> {
    const db = await this.getDB();
    const tx = db.transaction(QuantumPurse.STORE_CHILD_KEYS, "readonly");
    const store = tx.objectStore(QuantumPurse.STORE_CHILD_KEYS);
    const request = store.get(spxPubKey);
    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Retrieves all accounts from IndexedDB.
   * @returns A promise resolving to an array of SphincsPlusSigner objects.
   */
  public async getAccountList(): Promise<SphincsPlusSigner[]> {
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
   * Generates a new account derived from the master seed and sets it as the current signer.
   * @param password - The password to decrypt the master seed and encrypt the child key (will be zeroed out).
   * @returns A promise that resolves when the account is generated and set.
   * @throws Error if the master seed is not found or decryption fails.
   * @remark The password is overwritten with zeros after use for security.
   */
  public async genAccount(password: Uint8Array): Promise<void> {
    // Because decrypt by default will zero out the password, we need to clone the password.
    // Although this can be redesigned to let user decrypt master seed then derive keys,
    // it's more secure to do it in side this function automatically then dispose the password.
    const passwordClone = new Uint8Array(password);
    const childKeys = await this.getAccountList();
    const path = `pq/ckb/${childKeys.length}`;

    const packet = await this.getSeed();
    if (!packet) throw new Error("Master key (seed) not found!");

    const seed = await this.decrypt(password, packet); // password is cleared already by decrypt.
    if (!seed) throw new Error("Seed decryption failed!");

    // Using master seed to derive a different 48-byte seed for sphincs+ keygen.
    // This is basically key stretching from 256-bit master seed to 384 bit sphincs seed.
    // Bit-security isn't changed in this step.
    const sphincsSeed = await scryptAsync(
      seed,
      path,
      this.SCRYPT_PARAMS_FOR_SPX_KEY
    );
    seed.fill(0); // Clear sensitive data

    const sphincsPlusKey = slh_dsa_shake_128f.keygen(sphincsSeed);
    sphincsSeed.fill(0); // Clear sensitive data

    const encryptedChild = await this.encrypt(
      passwordClone,
      sphincsPlusKey.secretKey
    );
    passwordClone.fill(0); // Clear sensitive data
    sphincsPlusKey.secretKey.fill(0); // Clear sensitive data

    const currentAccount: SphincsPlusSigner = {
      sphincsPlusPubKey: uint8ArrayToHexString(sphincsPlusKey.publicKey),
      sphincsPlusPriEnc: encryptedChild,
    };

    await this.setAccount(currentAccount);
    this.signer = currentAccount;
  }

  /**
   * Sets the current signer for SPHINCS+ operations.
   * @param signer - The SPHINCS+ signer to set.
   */
  private setSigner(signer: SphincsPlusSigner): void {
    this.signer = signer;
  }

  /**
   * Calculates the entropy of an alphabetical password in bits.
   * @param password - The password as a Uint8Array (UTF-8 encoded). Will be zeroed out after processing.
   * @returns The entropy in bits (e.g., 1, 2, 128, 256, 444, etc.), or 0 for invalid/empty input.
   * @remark The input password is overwritten with zeros after calculation for security.
   */
  public static calculateEntropy(password: Uint8Array): number {
    if (!password || password.length === 0) {
      return 0;
    }

    const length = password.length;
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

    let poolSize = 0;
    if (hasLower) poolSize += 26; // Lowercase
    if (hasUpper) poolSize += 26; // Uppercase
    if (hasDigit) poolSize += 10; // Digits
    if (hasSymbol) poolSize += 32; // Symbols

    if (poolSize === 0) {
      poolSize = 1; // Minimum pool for all-same or uncategorized bytes (e.g., "aaa")
    }
    if (hasNonAscii) {
      poolSize = Math.max(poolSize, 94); // Minimum for full printable ASCII
      poolSize = Math.min(poolSize, 256); // Cap at byte max for UTF-8
    }

    const entropy = Math.floor(length * Math.log2(poolSize));
    password.fill(0);
    return entropy;
  }

  /**
   * Imports a seed phrase and stores it encrypted in IndexedDB, overwriting any existing seed.
   * @param seedPhrase - The seed phrase as a Uint8Array (UTF-8 encoded).
   * @param password - The password to encrypt the seed phrase (will be zeroed out).
   * @returns A promise that resolves when the seed is imported.
   * @remark SeedPhrase, password and sensitive data are overwritten with zeros after use for security.
   */
  public async importSeedPhrase(
    seedPhrase: Uint8Array,
    password: Uint8Array
  ): Promise<void> {
    const packet = await this.encrypt(password, seedPhrase);
    await this.setSeed(packet);
    // Clear sensitive data
    seedPhrase.fill(0);
    password.fill(0);
  }

  /**
   * Exports the wallet's seed phrase.
   * @param password - The password to decrypt the seed (will be zeroed out).
   * @returns A promise resolving to the seed phrase as a Uint8Array.
   * @throws Error if the master seed is not found or decryption fails.
   * @remark The password is overwritten with zeros after use. Handle the returned seed carefully to avoid leakage.
   */
  public async exportSeedPhrase(password: Uint8Array): Promise<Uint8Array> {
    const packet = await this.getSeed();
    if (!packet) throw new Error("Master key (seed) not found!");
    const seed = await this.decrypt(password, packet); // password is cleared already by decrypt.
    if (!seed) throw new Error("Master key (seed) decryption failed!");
    return seed;
  }
}