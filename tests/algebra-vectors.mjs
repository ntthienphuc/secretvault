// Small deterministic vectors for modular arithmetic; application keys use MODP3072.
import { modPow } from "../web/src/crypto.js";

export function inverse(value, modulus) {
  let a = ((value % modulus) + modulus) % modulus;
  let b = modulus;
  let x = 1n;
  let y = 0n;
  while (b) {
    const quotient = a / b;
    [a, b] = [b, a % b];
    [x, y] = [y, x - quotient * y];
  }
  if (a !== 1n) {
    throw new Error("No modular inverse");
  }
  return ((x % modulus) + modulus) % modulus;
}

export function classicElgamal({ p, g, a, m, k }) {
  const beta = modPow(g, a, p);
  const r = modPow(g, k, p);
  const secret = modPow(beta, k, p);
  const t = (secret * m) % p;
  const inv = inverse(modPow(r, a, p), p);
  return { beta, r, t, secret, inverse: inv, recovered: (t * inv) % p };
}

export function classicDh({ p, g, a, b }) {
  const A = modPow(g, a, p);
  const B = modPow(g, b, p);
  return { A, B, alice: modPow(B, a, p), bob: modPow(A, b, p) };
}

export async function algebraVectors() {
  const dh = classicDh({ p: 23n, g: 5n, a: 6n, b: 15n });
  const eg = classicElgamal({ p: 467n, g: 2n, a: 127n, m: 100n, k: 53n });
  const t2 = (eg.secret * 250n) % 467n;
  const recoveredM = (t2 * inverse(eg.t, 467n) * 100n) % 467n;
  return {
    dh,
    eg,
    pass:
      dh.A === 8n &&
      dh.B === 19n &&
      dh.alice === 2n &&
      dh.bob === 2n &&
      eg.beta === 132n &&
      eg.r === 399n &&
      eg.t === 308n &&
      eg.recovered === 100n &&
      recoveredM === 250n,
  };
}
