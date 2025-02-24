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

/**
 * Manages a wallet using the SPHINCS+ post-quantum signature scheme (shake-128f simple).
 * Implements a singleton pattern to ensure a single instance during runtime.
 */
class QuantumPurse {
  static readonly SPX_SIG_LEN: number = 17088; // SPHINCS+ shake 128f simple signature length
  static readonly MESSAGE_LEN: number = 32; // Message digest length (256-bit)
  static readonly ENTROPY_LEN: number = 48; // Entropy length for sphincs+ key gen
  static readonly DB_MASTER_KEY = "masterKey";
  static readonly DB_CHILD_KEYS = "childKeys";

  private SALT_LENGTH = 16; // 128-bit salt
  private IV_LENGTH = 12; // 96-bit IV for AES-GCM
  private SCRYPT_PARAMS_FOR_SEED = { N: 2 ** 16, r: 8, p: 1, dkLen: 32 };
  private SCRYPT_PARAMS_FOR_KDF = { N: 2 ** 16, r: 8, p: 1, dkLen: 48 };

  private signer?: PublicSphincs; // Current signer data
  private static instance: QuantumPurse | null = null; // Singleton instance
  public sphincsLock: { codeHash: string; hashType: HashType }; // SPHINCS+ lock script

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

  /** Generates the lock script for the current signer. */
  private getLockScript(): Script {
    if (!this.signer) throw new Error("Signer not available!");
    return {
      codeHash: this.sphincsLock.codeHash,
      hashType: this.sphincsLock.hashType,
      args: ckbHash(this.signer.sphincsPlusPubKey),
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
   * @param password - Password to decrypt the private key.
   * @returns Signed transaction.
   */
  public async sign(
    tx: TransactionSkeletonType,
    password: Uint8Array
  ): Promise<Transaction> {
    if (!this.signer) throw new Error("Signer not available!");

    const witnessLen =
      QuantumPurse.SPX_SIG_LEN + this.signer.sphincsPlusPubKey.length;
    tx = insertWitnessPlaceHolder(tx, witnessLen);
    tx = prepareSphincsPlusSigningEntries(tx);

    const signingEntries = tx.get("signingEntries").toArray();
    const privateKey = await this.decrypt(password, this.signer.packet);
    if (!privateKey) throw new Error("Failed to decrypt private key");

    const signature = slh_dsa_shake_128f.sign(
      privateKey,
      hexStringToUint8Array(signingEntries[0].message),
      this.genNonce()
    );
    privateKey.fill(0); // Clear sensitive data

    const serializedSignature = new Reader(signature.buffer).serializeJson();
    const serializedPublicKey = new Reader(
      hexStringToUint8Array(this.signer.sphincsPlusPubKey).buffer
    ).serializeJson();

    const witness =
      serializedSignature + serializedPublicKey.replace(/^0x/, "");
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

    const key = await scryptAsync(password, salt, this.SCRYPT_PARAMS_FOR_SEED);
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

    const key = await scryptAsync(password, salt, this.SCRYPT_PARAMS_FOR_SEED);
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
   * Clears a specific key from localStorage.
   * TODO Check security on localStorage + provide a password strength checking function.
   */
  public dbClear(dbKey: "masterKey" | "childKeys"): void {
    localStorage.removeItem(dbKey);
  }

  /**
   * Stores encrypted master key (seed) in localStorage.
   * @warning Overwrites existing data in localStorage.
   */
  public dbSetMasterKey(input: EncryptionPacket): void {
    localStorage.setItem(QuantumPurse.DB_MASTER_KEY, JSON.stringify(input));
  }

  /** Retrieves encrypted master key (seed) from localStorage. */
  public dbGetMasterKey(): EncryptionPacket | null {
    const localData = localStorage.getItem(QuantumPurse.DB_MASTER_KEY);
    return localData ? JSON.parse(localData) : null;
  }

  /** Stores encrypted child key data in localStorage. */
  public dbSetChildKey(input: PublicSphincs): void {
    const dbKey = QuantumPurse.DB_CHILD_KEYS;
    const localData = localStorage.getItem(dbKey);
    const packets: PublicSphincs[] = localData ? JSON.parse(localData) : [];

    if (packets.some((p) => p.sphincsPlusPubKey === input.sphincsPlusPubKey)) {
      return;
    }

    packets.push(input);
    localStorage.setItem(dbKey, JSON.stringify(packets));
  }

  /**
   * Retrieves a PublicSphincs object from local storage using a SPHINCS+ public key.
   * @param key - The SPHINCS+ public key to look up in DB.
   * @returns The matching PublicSphincs object, or null.
   */
  public dbGetChildKey(key: string): PublicSphincs | null {
    const dbKey = QuantumPurse.DB_CHILD_KEYS;
    const localData = localStorage.getItem(dbKey);
    if (!localData) return null;
    try {
      const packets: PublicSphincs[] = JSON.parse(localData);
      return packets.find((p) => p.sphincsPlusPubKey === key) ?? null;
    } catch (error) {
      console.error(`Failed to retrieve data for "${dbKey}":`, error);
      return null;
    }
  }

  /** Retrieves all child key data from localStorage. */
  public dbGetChildKeys(): PublicSphincs[] {
    const dbKey = QuantumPurse.DB_CHILD_KEYS;
    const localData = localStorage.getItem(dbKey);
    if (!localData) return [];
    try {
      return JSON.parse(localData);
    } catch (error) {
      console.error(`Failed to retrieve data for ${dbKey}:`, error);
      return [];
    }
  }

  /**
   * Creates a new account derived from the master key (seed).
   * @param password - Password to decrypt the encrypted master key (seed) and encrypt the child key.
   */
  public async deriveChildKey(password: Uint8Array): Promise<void> {
    const localData = this.dbGetChildKeys();
    const path = `pq/ckb/${localData.length}`;

    const packet = this.dbGetMasterKey();
    if (!packet) throw new Error("Master key (seed) not found!");

    const seed = await this.decrypt(password, packet);
    if (!seed)
      throw new Error("Seed decryption failed. Please check your password!");

    const sphincsSeed = await scryptAsync(
      seed,
      path,
      this.SCRYPT_PARAMS_FOR_KDF
    );
    const sphincsPlusKey = slh_dsa_shake_128f.keygen(sphincsSeed);
    sphincsPlusKey.secretKey.fill(0); // Clear sensitive data

    const encryptedChild = await this.encrypt(password, sphincsSeed);
    const currentAccount: PublicSphincs = {
      sphincsPlusPubKey: uint8ArrayToHexString(sphincsPlusKey.publicKey),
      packet: encryptedChild,
    };

    this.dbSetChildKey(currentAccount);
    this.signer = currentAccount;

    password.fill(0); // Clear sensitive data
    seed.fill(0);
    sphincsSeed.fill(0);
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
   * @todo Implement this method.
   */
  public importSeedPhrase(seedPhrase: string): void {}

  /**
   * Exports a wallet's seed phrase.
   * @param walletId - Wallet ID to export.
   * @todo Implement this method.
   */
  public exportSeedPhrase(walletId: string): void {}
}

export default QuantumPurse;
