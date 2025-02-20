import * as bip39 from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { scryptAsync } from "@noble/hashes/scrypt";
import { hexStringToUint8Array, uint8ArrayToHexString } from "./utils";

class KeyManager {
  private static SALT_LENGTH = 16; // 128-bit salt
  private static SCRYPT_PARAMS_FOR_SEED = { N: 2 ** 16, r: 8, p: 1, dkLen: 32 };
  private static SCRYPT_PARAMS_FOR_KDF = { N: 2 ** 16, r: 8, p: 1, dkLen: 48 };
  private static IV_LENGTH = 12; // 96-bit IV for AES-GCM

  public static DB_MASTER_KEY = "masterKey";
  public static DB_CHILD_KEYS = "childKeys";

  constructor() {}

  /**
   * Cleans the localStorage by removing all keys associated with this application.
   * @returns void
   */
  public cleanStorage(): void {
    // Remove specific keys used by your application
    localStorage.removeItem(KeyManager.DB_MASTER_KEY);
    localStorage.removeItem(KeyManager.DB_CHILD_KEYS);
  }

  /**
   * Generate a new 24 word seed phrase for max 256bit security.
   * @returns seed phrase object
   */
  public generateSeedPhrase(): string {
    return bip39.generateMnemonic(wordlist, 256);
  }

  /**
   * This function Encrypts input data and store the encrypted in local device.
   * At this point, validation for a strong password MUST be done beforehand.
   * @param password - The password used to encrypt the input data.
   * @param input - The data to be encrypted.
   * @param dbKey - The key in k-v storage.
   * @returns none
   */
  public async encryptAndStore(
    password: Uint8Array,
    input: Uint8Array,
    dbKey: string
  ) {
    // Generate salt, iv
    const salt = new Uint8Array(KeyManager.SALT_LENGTH);
    const iv = new Uint8Array(KeyManager.IV_LENGTH);
    globalThis.crypto.getRandomValues(salt);
    globalThis.crypto.getRandomValues(iv);

    // Derive scrypt key
    const key = await scryptAsync(
      password,
      salt,
      KeyManager.SCRYPT_PARAMS_FOR_SEED
    );

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

    // build store packet
    const packet = {
      salt: uint8ArrayToHexString(salt),
      iv: uint8ArrayToHexString(iv),
      ciphertext: uint8ArrayToHexString(new Uint8Array(encryptedData)),
    };

    // Retrieve existing data from local storage
    const localData = localStorage.getItem(dbKey);
    let packets = localData ? JSON.parse(localData) : [];

    // Append the new store structure
    packets.push(packet);

    // Store locally
    localStorage.setItem(dbKey, JSON.stringify(packets));

    // Zero out sensitive buffers
    password.fill(0);
    input.fill(0);
  }

  /**
   * Loads and decrypts the encrypted data using AES-GCM and a password-derived key.
   *
   * @param password - The user's password in Uint8Array format.
   * @param dbKey - The key in k-v storage.
   * @param index - The index of the encrypted data in the array (default: 0).
   * @returns {Promise<Uint8Array | null>} - The decrypted data.
   *
   * @throws {Error} - If decryption fails due to incorrect password or corrupted data.
   */
  public async loadAndDecrypt(
    password: Uint8Array,
    dbKey: string,
    index: number = 0
  ): Promise<Uint8Array | null> {
    // Retrieve encrypted data from storage
    const localData = localStorage.getItem(dbKey);
    if (!localData) {
      return null; // No data found
    }

    const packets = JSON.parse(localData);
    if (!Array.isArray(packets) || index >= packets.length) {
      return null; // Invalid data or index
    }

    const packet = packets[index];
    const salt = hexStringToUint8Array(packet.salt);
    const iv = hexStringToUint8Array(packet.iv);
    const ciphertext = hexStringToUint8Array(packet.ciphertext);

    // Derive the scrypt key
    const key = await scryptAsync(
      password,
      salt,
      KeyManager.SCRYPT_PARAMS_FOR_SEED
    );

    // Import key for decryption
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      "raw",
      key,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    try {
      // Decrypt the ciphertext
      const decryptedData = await globalThis.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        cryptoKey,
        ciphertext
      );

      // Zero out the sensitive data
      password.fill(0);

      return new Uint8Array(decryptedData);
    } catch (error) {
      console.error("Decryption failed:", error);
      return null;
    }
  }

  /**
   * Create a new account derived from the wallet's seed phrase
   * @returns Account object
   */
  public async createAccount(password: Uint8Array) {
    const localKeys = localStorage.getItem(KeyManager.DB_CHILD_KEYS);
    console.log(">>>mark1 | localKeys: ", localKeys);
    let packets = [];
    if (localKeys) {
      console.log(">>>mark2");
      packets = JSON.parse(localKeys);
    }

    const path = `pq/ckb/${packets.length}`;
    console.log(">>>mark3 | path: ", path);

    // load up seed and decrypt
    const seed = await this.loadAndDecrypt(password, KeyManager.DB_MASTER_KEY);

    if (!seed) throw new Error("Seed decryption failed");

    // Derive 48-byte key using scrypt for sphincs+ key gen, using path as salt for determinism
    const sphincsSeed = await scryptAsync(
      seed,
      path,
      KeyManager.SCRYPT_PARAMS_FOR_KDF
    );

    // encrypt key and store it
    await this.encryptAndStore(password, sphincsSeed, KeyManager.DB_CHILD_KEYS);

    // Zero out the sensitive data
    password.fill(0);
    seed.fill(0);
    sphincsSeed.fill(0);
  }

  /**
   * List accounts for a given wallet
   * @param walletId - The wallet ID
   * @returns List of accounts
   */
  public listAccounts(walletId: string) {}

  /**
   * Import a wallet using a provided seed phrase
   * @param seedPhrase - The seed phrase
   * @returns Imported wallet ID
   */
  importSeedPhrase(seedPhrase: string) {}

  /**
   * Export a wallet's seed phrase
   * @param walletId - The wallet ID
   * @returns Seed phrase
   */
  exportSeedPhrase(walletId: string) {}
}

export default KeyManager;
