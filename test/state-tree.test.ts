import { describe, it, expect } from 'vitest';
import { AgentStateTree, verifyInclusionPath } from '../src/state-tree.js';
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

describe('action inclusion paths', () => {
  const leaves = ['11', '22', '33', '44', '55'].map(x => ('0x' + x.repeat(32)) as Hex);
  for (const size of [1, 2, 3, 4, 5]) {
    it(`reconstructs the root for every index at size ${size}`, () => {
      const tree = new AgentStateTree(leaves.slice(0, size));
      for (let index = 0; index < size; index++) {
        let hash = keccak256(concatHex(['0x00', leaves[index]]));
        for (const step of tree.getInclusionPath(index)) {
          const pair = step.position === 'left' ? [step.hash, hash] : [hash, step.hash];
          hash = keccak256(concatHex(['0x01', ...pair]));
        }
        expect(hash).toBe(tree.getRoot());
      }
    });
  }

  it('rebuilds proofs after appends and isolates previously returned paths', () => {
    const tree = new AgentStateTree();
    for (const [index, leaf] of leaves.entries()) {
      tree.insertActionLeaf(leaf);
      const root = new AgentStateTree(leaves.slice(0, index + 1)).getRoot();
      expect(tree.getRoot()).toBe(root);
      for (let i = 0; i <= index; i++) {
        const path = tree.getInclusionPath(i);
        expect(verifyInclusionPath(leaves[i], path, root)).toBe(true);
        if (path.length) path[0].hash = '0x';
        expect(verifyInclusionPath(leaves[i], tree.getInclusionPath(i), root)).toBe(true);
      }
    }
  });

  it('rejects indices without an existing leaf', () => {
    const tree = new AgentStateTree(leaves);
    for (const index of [-1, 0.5, NaN, Infinity, leaves.length]) {
      expect(() => tree.getInclusionPath(index)).toThrow(RangeError);
    }
    expect(() => new AgentStateTree().getInclusionPath(0)).toThrow(RangeError);
  });
});

describe('verifyInclusionPath', () => {
  const leaves = ['ab', 'cd', 'ef'].map(x => ('0x' + x.repeat(32)) as Hex);
  const tree = new AgentStateTree(leaves);
  const root = tree.getRoot();
  const path = tree.getInclusionPath(0);

  it('checks disclosures against a trusted root, including odd and singleton trees', () => {
    for (const [i, leaf] of leaves.entries()) {
      expect(verifyInclusionPath(leaf, tree.getInclusionPath(i), root)).toBe(true);
    }
    const one = new AgentStateTree([leaves[0]]);
    expect(verifyInclusionPath(leaves[0], [], one.getRoot())).toBe(true);
    expect(verifyInclusionPath(leaves[0], path, ('0x' + root.slice(2).toUpperCase()) as Hex)).toBe(true);
  });

  it('rejects altered leaves, roots, step order, side and hash', () => {
    expect(verifyInclusionPath(leaves[1], path, root)).toBe(false);
    expect(verifyInclusionPath(leaves[0], path, leaves[1])).toBe(false);
    expect(verifyInclusionPath(leaves[0], [...path].reverse(), root)).toBe(false);
    expect(verifyInclusionPath(leaves[0], [{...path[0], position: 'left'}, path[1]], root)).toBe(false);
    expect(verifyInclusionPath(leaves[0], [{...path[0], hash: leaves[0]}, path[1]], root)).toBe(false);
  });

  it('rejects malformed values received from JSON', () => {
    for (const input of ['null', '[null]', '[{}]', '[{"hash":"0x00","position":"left"}]']) {
      expect(verifyInclusionPath(leaves[0], JSON.parse(input), root)).toBe(false);
    }
    expect(verifyInclusionPath('0x01', path, root)).toBe(false);
    expect(verifyInclusionPath(leaves[0], path, '0x')).toBe(false);
  });
});
