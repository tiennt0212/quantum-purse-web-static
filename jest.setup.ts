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
  };
});
