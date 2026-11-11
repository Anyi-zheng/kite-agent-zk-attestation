import { describe, it, expect } from 'vitest';
import { AgentStateTree } from '../src/state-tree.js';
import { type Hex } from 'viem';
import { concatHex, keccak256 } from 'viem';

describe('AgentStateTree', () => {
  it('returns zero root for empty tree', () => {
    const tree = new AgentStateTree();
    expect(tree.getRoot()).toBe('0x0000000000000000000000000000000000000000000000000000000000000000');
  });

  it('aggregates single action leaf into root', () => {
    const leaf = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef' as Hex;
    const tree = new AgentStateTree([leaf]);
    expect(tree.getRoot()).toBe(keccak256(concatHex(['0x00', leaf])));
  });

  it('computes deterministic multi-level Merkle root', () => {
    const leafA = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' as Hex;
    const leafB = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' as Hex;
    const tree1 = new AgentStateTree([leafA, leafB]);
    const tree2 = new AgentStateTree([leafA, leafB]);

    expect(tree1.getRoot()).toBe(tree2.getRoot());
    expect(tree1.getRoot()).not.toBe(leafA);
  });

  it('commits every leaf and its order, including odd-width levels', () => {
    const leaves = ['11', '22', '33', '44', '55'].map(x => ('0x' + x.repeat(32)) as Hex);
    const root = new AgentStateTree(leaves).getRoot();
    for (let i = 0; i < leaves.length; i++) {
      const changed = [...leaves];
      changed[i] = ('0x' + 'ff'.repeat(32)) as Hex;
      expect(new AgentStateTree(changed).getRoot()).not.toBe(root);
    }
    expect(new AgentStateTree([...leaves].reverse()).getRoot()).not.toBe(root);
    expect(new AgentStateTree(leaves.slice(0, -1)).getRoot()).not.toBe(root);
  });

  it('matches the domain-separated two-leaf vector', () => {
    const a = ('0x' + '11'.repeat(32)) as Hex;
    const b = ('0x' + '22'.repeat(32)) as Hex;
    const expected = keccak256(concatHex(['0x01', keccak256(concatHex(['0x00', a])), keccak256(concatHex(['0x00', b]))]));
    expect(new AgentStateTree([a, b]).getRoot()).toBe(expected);
    expect(new AgentStateTree([a, b]).getRoot()).not.toBe(b);
  });

  it('rejects malformed leaves at construction and insertion', () => {
    for (const leaf of ['0x12', 'not-hex', '0x' + 'gg'.repeat(32)]) {
      expect(() => new AgentStateTree([leaf as Hex])).toThrow('32-byte');
      expect(() => new AgentStateTree().insertActionLeaf(leaf as Hex)).toThrow('32-byte');
    }
  });
});
