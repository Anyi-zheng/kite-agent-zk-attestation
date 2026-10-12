import { z } from 'zod';
import { type Hex, isHex } from 'viem';

export const AgentExecutionProofSchema = z.object({
  agentId: z.string().refine((val): val is Hex => isHex(val) && val.length === 66, {
    message: 'agentId must be a 32-byte hex string (0x...)',
  }),
  stateHash: z.string().refine((val): val is Hex => isHex(val) && val.length === 66, {
    message: 'stateHash must be a 32-byte hex string (0x...)',
  }),
  computationEpoch: z.bigint().min(1n),
  x402ReceiptHash: z.string().refine((val): val is Hex => isHex(val) && val.length === 66, {
    message: 'x402ReceiptHash must be a 32-byte hex string (0x...)',
  }),
  zkProof: z.string().refine((val): val is Hex => isHex(val), {
    message: 'zkProof must be a valid hex string',
  }),
  timestamp: z.number().int().positive().optional(),
});

export type AgentExecutionProof = z.infer<typeof AgentExecutionProofSchema>;

export interface AttestationVerificationResult {
  valid: boolean;
  attestationDigest: Hex;
  epoch: bigint;
  agentId: Hex;
  rejectionReason?: string;
}

export interface KiteNetworkConfig {
  name: string;
  chainId: number;
  rpcUrl: string;
  contractAddress: Hex;
  facilitatorUrl: string;
}

export const KITE_TESTNET_CONFIG: KiteNetworkConfig = {
  name: 'Kite Testnet',
  chainId: 2368,
  rpcUrl: 'https://rpc-testnet.gokite.ai',
  contractAddress: '0x89C57532A1553fbe98A008Fe3960098f9E7C0572',
  facilitatorUrl: 'https://facilitator-testnet.gokite.ai',
};

export const KITE_MAINNET_CONFIG: KiteNetworkConfig = {
  name: 'Kite Mainnet',
  chainId: 2366,
  rpcUrl: 'https://rpc.gokite.ai',
  contractAddress: '0x2A1553fbe98A008Fe3960098f9E7C057289C5753',
  facilitatorUrl: 'https://facilitator.gokite.ai',
};
