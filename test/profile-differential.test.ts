import { test, expect } from 'bun:test';
import { hashRaw } from '../src/index.ts';

test('optimized Wasm matches native ref.c for full, reduced and lane-boundary profiles', async () => {
  const cases = [
    [19456,3,1], [19456,2,1], [12288,3,1], [9216,4,1], [7168,5,1],
    [8192,1,1], [4096,2,1], [4096,1,1], [2048,2,1], [2048,1,1],
    [8,1,1], [19,2,2], [35,3,4], [129,1,16], [32768,1,4],
  ] as const;
  const oracle = new Uint8Array(await Bun.file(new URL('./fixtures/profile-oracle.bin', import.meta.url)).arrayBuffer());
  expect(oracle.length).toBe(cases.length*32);
  for (const [i,[memoryCost,timeCost,parallelism]] of cases.entries()) {
    const tag=await hashRaw(Uint8Array.from({length:32},(_,j)=>(j*17+i)&255),{
      salt:new Uint8Array(16).fill(2), secret:new Uint8Array(8).fill(3),
      associatedData:new Uint8Array(12).fill(4),memoryCost,timeCost,parallelism,
    });
    expect(tag.length===32 && tag.every((v,j)=>v===oracle[i*32+j])).toBe(true);
  }
});
