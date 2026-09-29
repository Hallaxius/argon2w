import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { verify } from "../src/index.ts";

const DIR = join(import.meta.dir, "..", "docker", "fuzz-corpus");
const WRONG = "definitely-not-the-corpus-password-0123456789";

const FILES = readdirSync(DIR).sort();

describe("C fuzz corpus through verify()", () => {
  test("corpus is complete (no fixture silently dropped)", () => {
    expect(FILES.length).toBeGreaterThanOrEqual(20);
    expect(FILES).toContain("valid.phc");
    expect(FILES).toContain("nearcap.phc");
    expect(FILES).toContain("maxtime.phc");
  });

  test("valid.phc keeps its documented shape", () => {
    const content = readFileSync(join(DIR, "valid.phc"), "utf8");
    expect(content.startsWith("$argon2id$v=19$m=8,t=1,p=1$")).toBe(true);
  });

  test("every corpus file resolves to a boolean without throwing", async () => {
    for (const name of FILES) {
      const content = readFileSync(join(DIR, name), "utf8");
      const result = await verify(content, WRONG);
      expect(typeof result).toBe("boolean");
    }
  });

  test("a wrong password is false for every corpus file", async () => {
    for (const name of FILES) {
      const content = readFileSync(join(DIR, name), "utf8");
      expect(await verify(content, WRONG)).toBe(false);
    }
  });
});
