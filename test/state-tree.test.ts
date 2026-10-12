import { describe, it, expect } from 'vitest';
import { AgentStateTree } from '../src/state-tree.js';
import { type Hex } from 'viem';

describe('AgentStateTree', () => {
  it('returns zero root for empty tree', () => {
    const tree = new AgentStateTree();
    expect(tree.getRoot()).toBe('0x0000000000000000000000000000000000000000000000000000000000000000');
  });

  it('aggregates single action leaf into root', () => {
    const leaf = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef' as Hex;
    const tree = new AgentStateTree([leaf]);
    expect(tree.getRoot()).toBe(leaf);
  });

  it('computes deterministic multi-level Merkle root', () => {
    const leafA = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' as Hex;
    const leafB = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' as Hex;
    const tree1 = new AgentStateTree([leafA, leafB]);
    const tree2 = new AgentStateTree([leafA, leafB]);

    expect(tree1.getRoot()).toBe(tree2.getRoot());
    expect(tree1.getRoot()).not.toBe(leafA);
  });
});
