// export const CKB_INDEXER_URL = "http://localhost:8114/indexer";
// export const NODE_URL = "http://localhost:8114";
export const CKB_INDEXER_URL = "https://testnet.ckb.dev/indexer";
export const NODE_URL = "https://testnet.ckb.dev/";
export const FEE_RATE = BigInt(1500);
export const IS_MAIN_NET = false;

export const DEV_KEY = {
  pubkey: new Uint8Array([
    90, 52, 158, 154, 41, 47, 118, 162, 7, 6, 125, 163, 245, 37, 87, 206, 153,
    4, 70, 82, 213, 185, 223, 110, 123, 41, 252, 50, 47, 252, 217, 89,
  ]),
  prikey: new Uint8Array([
    93, 154, 155, 80, 203, 74, 178, 95, 128, 194, 205, 204, 141, 143, 126, 186,
    153, 186, 160, 5, 237, 94, 209, 101, 167, 37, 95, 29, 97, 219, 146, 236, 90,
    52, 158, 154, 41, 47, 118, 162, 7, 6, 125, 163, 245, 37, 87, 206, 153, 4,
    70, 82, 213, 185, 223, 110, 123, 41, 252, 50, 47, 252, 217, 89,
  ]),
};

// TODO replace smart contract when deployed
export const SPHINCSPLUS_LOCK = {
  codeHash:
    "0xe48e518e7db3c44d1e13cb57d2d16eaea721d5e4d329d73d20181c4e490420b7",
  hashType: "data1",
  outPoint: {
    txHash:
      "0xfdefc406a81a51bb672e552ccce6117516b3917b0cdff538faccc4e828b0ae12",
    index: "0x0",
  },
  depType: "code",
};
