import { readFileSync } from "fs";
import path from "path";
import { getCreate2Address, keccak256, solidityPacked, toUtf8Bytes } from "ethers";

/** Arachnid deterministic deployment proxy — same address on COTI testnet and mainnet. */
export const DETERMINISTIC_DEPLOYMENT_PROXY =
  "0x4e59b44847b379578588920cA78FbF26c0B4956C";

/** Documented salt label; do not change after first deploy. */
export const AES_KEY_BACKUP_VAULT_SALT_LABEL = "coti.io:AesKeyBackupVault:v1";

export const AES_KEY_BACKUP_VAULT_SALT = keccak256(
  toUtf8Bytes(AES_KEY_BACKUP_VAULT_SALT_LABEL),
);

export function getAesKeyBackupVaultBytecode(): string {
  const artifactPath = path.join(
    __dirname,
    "../artifacts/contracts/onboard/AesKeyBackupVault.sol/AesKeyBackupVault.json",
  );
  const artifact = JSON.parse(readFileSync(artifactPath, "utf8")) as {
    bytecode: string;
  };
  if (!artifact.bytecode || artifact.bytecode === "0x") {
    throw new Error(
      "AesKeyBackupVault artifact missing bytecode. Run `npx hardhat compile` first.",
    );
  }
  return artifact.bytecode;
}

export function predictAesKeyBackupVaultAddress(bytecode: string): string {
  return getCreate2Address(
    DETERMINISTIC_DEPLOYMENT_PROXY,
    AES_KEY_BACKUP_VAULT_SALT,
    keccak256(bytecode),
  );
}

export function buildDeterministicDeployData(bytecode: string): string {
  return solidityPacked(["bytes32", "bytes"], [AES_KEY_BACKUP_VAULT_SALT, bytecode]);
}
