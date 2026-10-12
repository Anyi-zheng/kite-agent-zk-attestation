import { type Hex, hexToBytes, toHex } from 'viem';

export interface MerkleStep {
  hash: Hex;
  position: 'left' | 'right';
}

/**
 * Utility for aggregating agent execution actions into a Merkle digest
 */
export class AgentStateTree {
  private leaves: Hex[] = [];

  constructor(initialLeaves: Hex[] = []) {
    this.leaves = [...initialLeaves];
  }

  public insertActionLeaf(actionHash: Hex): void {
    this.leaves.push(actionHash);
  }

  public getLeafCount(): number {
    return this.leaves.length;
  }

  public getRoot(): Hex {
    if (this.leaves.length === 0) {
      return ('0x' + '0'.repeat(64)) as Hex;
    }
    let currentLevel = [...this.leaves];

    while (currentLevel.length > 1) {
      const nextLevel: Hex[] = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        if (i + 1 < currentLevel.length) {
          nextLevel.push(this.hashPair(currentLevel[i], currentLevel[i + 1]));
        } else {
          nextLevel.push(currentLevel[i]);
        }
      }
      currentLevel = nextLevel;
    }

    return currentLevel[0];
  }

  private hashPair(a: Hex, b: Hex): Hex {
    const bytesA = hexToBytes(a);
    const bytesB = hexToBytes(b);
    const combined = new Uint8Array(bytesA.length + bytesB.length);
    combined.set(bytesA);
    combined.set(bytesB, bytesA.length);
    
    // Simple deterministic fold representation for demo
    let val = 0n;
    for (const byte of combined) {
      val = (val << 8n) + BigInt(byte);
    }
    return ('0x' + (val % (2n ** 256n)).toString(16).padStart(64, '0')) as Hex;
  }
}
