import wasmModule from "@hallaxius/argon2w/wasm";
import {
  assessRehash,
  bytesToHex,
  configureWasm,
  createProfile,
  hash,
  hashRaw,
  needsRehash,
  profiles,
  verify,
} from "@hallaxius/argon2w";

configureWasm(wasmModule);

const PASSWORD = new Uint8Array(32).fill(1);
const SALT = new Uint8Array(16).fill(2);
const EXPECTED = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659";

export default {
  async fetch() {
    const tag = await hashRaw(PASSWORD, {
      salt: SALT,
      secret: new Uint8Array(8).fill(3),
      associatedData: new Uint8Array(12).fill(4),
      timeCost: 3,
      memoryCost: 32,
      parallelism: 4,
      hashLength: 32,
    });
    const hex = bytesToHex(tag);
    const encoded = await hash("consumer-pw", {
      profile: "experimental",
    });
    const custom = createProfile({ memoryCost: 8192, timeCost: 1, parallelism: 1, hashLength: 32 });
    const ok =
      hex === EXPECTED &&
      profiles.experimental.memoryCost === 2048 &&
      (await verify(encoded, "consumer-pw")) &&
      !(await verify(encoded, "wrong")) &&
      assessRehash(encoded, "experimental") === "matches" &&
      assessRehash(encoded, custom) === "below-target" &&
      !needsRehash(encoded, profiles.experimental);
    return new Response(ok ? "CONSUMER-OK" : "CONSUMER-FAIL", {
      status: ok ? 200 : 500,
      headers: { "content-type": "text/plain" },
    });
  },
};
