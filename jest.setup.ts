import { TextEncoder, TextDecoder } from 'util';
Object.assign(global, { TextDecoder, TextEncoder });

jest.mock("./src/core/config.ts", () => {
  const originalModule = jest.requireActual("./src/core/config.ts");
  return {
    ...originalModule,
    CKB_INDEXER_URL: "http://localhost:8114/indexer",
    NODE_URL: "http://localhost:8114",
    SPHINCSPLUS_LOCK: {
      ...originalModule.SPHINCSPLUS_LOCK,
      outPoint: {
        ...originalModule.SPHINCSPLUS_LOCK.outPoint,
        txHash:
          "0xe51c3616ce1244ed32a8b3d65343d11c838afde1b711810edcf6e5236de57c87",
      },
    },
    DEV_KEY: {
      pubkey: new Uint8Array([
        90, 52, 158, 154, 41, 47, 118, 162, 7, 6, 125, 163, 245, 37, 87, 206,
        153, 4, 70, 82, 213, 185, 223, 110, 123, 41, 252, 50, 47, 252, 217, 89,
      ]),
      prikey: new Uint8Array([
        93, 154, 155, 80, 203, 74, 178, 95, 128, 194, 205, 204, 141, 143, 126,
        186, 153, 186, 160, 5, 237, 94, 209, 101, 167, 37, 95, 29, 97, 219, 146,
        236, 90, 52, 158, 154, 41, 47, 118, 162, 7, 6, 125, 163, 245, 37, 87,
        206, 153, 4, 70, 82, 213, 185, 223, 110, 123, 41, 252, 50, 47, 252, 217,
        89,
      ]),
    },
  };
});
