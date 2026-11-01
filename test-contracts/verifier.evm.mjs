import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs/promises';
import solc from 'solc';
import ganache from 'ganache';
import { createPublicClient, createWalletClient, custom, defineChain, encodeDeployData, getContract, zeroAddress } from 'viem';

test('verifier configuration and proof rejection on a private, in-process EVM', async t => {
  const sources = {};
  for (const file of ['KiteAgentZKAttestation.sol', 'MockGroth16Verifier.sol']) {
    sources[file] = { content: await fs.readFile(new URL('../contracts/' + file, import.meta.url), 'utf8') };
  }
  const output = JSON.parse(solc.compile(JSON.stringify({ language: 'Solidity', sources,
    settings: { evmVersion: 'shanghai', outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } } })));
  assert.deepEqual((output.errors ?? []).filter(e => e.severity === 'error'), []);
  const provider = ganache.provider({ logging: { quiet: true }, chain: { chainId: 1337, hardfork: 'shanghai' }, wallet: { deterministic: true } });
  try {
    const chain = defineChain({ id: 1337, name: 'Private contract test', nativeCurrency: { name: 'Test', symbol: 'TEST', decimals: 18 }, rpcUrls: { default: { http: ['http://127.0.0.1'] } } });
    const publicClient = createPublicClient({ chain, transport: custom(provider) });
    const wallet = createWalletClient({ chain, transport: custom(provider) });
    const [owner, other] = await wallet.getAddresses();
    const artifact = (file, name) => ({ abi: output.contracts[file][name].abi, bytecode: '0x' + output.contracts[file][name].evm.bytecode.object });
    const registryArtifact = artifact('KiteAgentZKAttestation.sol', 'KiteAgentZKAttestation');
    const deploy = async (code, args = []) => {
      const hash = await wallet.deployContract({ ...code, args, account: owner, gas: 3_000_000n });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      assert.equal(receipt.status, 'success');
      return getContract({ address: receipt.contractAddress, abi: code.abi, client: { public: publicClient, wallet } });
    };
    await t.test('zero-address and EOA verifier constructors revert', async () => {
      for (const verifier of [zeroAddress, other]) {
        await assert.rejects(publicClient.estimateGas({ account: owner, data: encodeDeployData({ ...registryArtifact, args: [verifier] }) }));
      }
    });
    const mock = await deploy(artifact('MockGroth16Verifier.sol', 'MockGroth16Verifier'));
    const registry = await deploy(registryArtifact, [mock.address]);
    await t.test('updates reject missing code and unauthorized accounts', async () => {
      for (const verifier of [zeroAddress, other]) {
        await assert.rejects(registry.simulate.setVerifier([verifier], { account: owner }));
      }
      await assert.rejects(registry.simulate.setVerifier([mock.address], { account: other }));
      assert.equal((await registry.read.verifier()).toLowerCase(), mock.address.toLowerCase());
    });
    const args = ['0x' + '11'.repeat(32), '0x' + '22'.repeat(32), 1n, '0x' + '33'.repeat(32), '0x' + '44'.repeat(32)];
    await t.test('a rejected mock proof cannot advance an epoch', async () => {
      await publicClient.waitForTransactionReceipt({ hash: await mock.write.setShouldPass([false], { account: owner }) });
      await assert.rejects(registry.simulate.anchorAttestation(args, { account: owner }));
      assert.equal(await registry.read.agentLatestEpoch([args[0]]), 0n);
    });
    await t.test('an explicitly configured test verifier can accept a proof', async () => {
      await publicClient.waitForTransactionReceipt({ hash: await mock.write.setShouldPass([true], { account: owner }) });
      const receipt = await publicClient.waitForTransactionReceipt({ hash: await registry.write.anchorAttestation(args, { account: owner, gas: 500_000n }) });
      assert.equal(receipt.status, 'success');
      assert.equal(await registry.read.agentLatestEpoch([args[0]]), 1n);
    });
  } finally {
    await provider.disconnect();
  }
});
