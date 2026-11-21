import { type Hex, concatHex, keccak256 } from 'viem';

export interface MerkleStep {
  hash: Hex;
  position: 'left' | 'right';
}

function isDigest(value: unknown): value is Hex {
  return typeof value === 'string' && /^0x[0-9a-fA-F]{64}$/.test(value);
}

function hashLeaf(leaf: Hex): Hex {
  return keccak256(concatHex(['0x00', leaf]));
}

function hashPair(left: Hex, right: Hex): Hex {
  return keccak256(concatHex(['0x01', left, right]));
}

/** Check a disclosed action against an independently trusted Kite state root. */
export function verifyInclusionPath(action: Hex, path: readonly MerkleStep[], root: Hex): boolean {
  if (!isDigest(action) || !isDigest(root) || !Array.isArray(path)) return false;

  let node = hashLeaf(action);
  for (const step of path) {
    if (!isDigest(step?.hash)) return false;
    if (step.position === 'left') node = hashPair(step.hash, node);
    else if (step.position === 'right') node = hashPair(node, step.hash);
    else return false;
  }
  return node === root.toLowerCase();
}

/**
 * Utility for aggregating agent execution actions into a Merkle digest
 */
export class AgentStateTree {
  private leaves: Hex[] = [];
  private levels?: Hex[][];

  constructor(initialLeaves: Hex[] = []) {
    initialLeaves.forEach((leaf) => this.validateLeaf(leaf));
    this.leaves = [...initialLeaves];
  }

  public insertActionLeaf(actionHash: Hex): void {
    this.validateLeaf(actionHash);
    this.leaves.push(actionHash);
    this.levels = undefined;
  }

  public getLeafCount(): number {
    return this.leaves.length;
  }

  public getRoot(): Hex {
    if (this.leaves.length === 0) {
      return ('0x' + '0'.repeat(64)) as Hex;
    }
    const levels = this.getLevels();
    return levels[levels.length - 1][0];
  }

  /** Sibling hashes ordered from the leaf toward the root. */
  public getInclusionPath(index: number): MerkleStep[] {
    if (!Number.isSafeInteger(index) || index < 0 || index >= this.leaves.length) {
      throw new RangeError('Leaf index outside the state tree');
    }
    const steps: MerkleStep[] = [];
    for (const level of this.getLevels()) {
      const isRight = index % 2 === 1;
      const sibling = isRight ? index - 1 : index + 1;
      if (sibling < level.length) {
        steps.push({ hash: level[sibling], position: isRight ? 'left' : 'right' });
      }
      index = Math.floor(index / 2);
    }
    return steps;
  }

  private getLevels(): Hex[][] {
    if (this.levels) return this.levels;
    let currentLevel = this.leaves.map(hashLeaf);
    const levels = [currentLevel];
    while (currentLevel.length > 1) {
      const nextLevel: Hex[] = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        if (i + 1 < currentLevel.length) {
          nextLevel.push(hashPair(currentLevel[i], currentLevel[i + 1]));
        } else {
          nextLevel.push(currentLevel[i]);
        }
      }
      levels.push(nextLevel);
      currentLevel = nextLevel;
    }

    this.levels = levels;
    return levels;
  }

  private validateLeaf(leaf: Hex): void {
    if (!isDigest(leaf)) {
      throw new Error('Action leaves must be 32-byte hex digests');
    }
  }
}
