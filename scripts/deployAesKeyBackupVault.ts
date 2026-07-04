import { ethers } from "hardhat";
import {
  buildDeterministicDeployData,
  DETERMINISTIC_DEPLOYMENT_PROXY,
  getAesKeyBackupVaultBytecode,
  predictAesKeyBackupVaultAddress,
} from "./aesKeyBackupVaultCreate2";

async function main() {
  const [deployer] = await ethers.getSigners();
  if (!deployer) {
    throw new Error("No deployer signer found. Set PRIVATE_KEY in your environment.");
  }

  const provider = deployer.provider;
  if (!provider) {
    throw new Error("No provider found for deployer signer.");
  }

  const bytecode = await getAesKeyBackupVaultBytecode();
  const predictedAddress = predictAesKeyBackupVaultAddress(bytecode);
  const existingCode = await provider.getCode(predictedAddress);

  console.log("Deploying AesKeyBackupVault via CREATE2...");
  console.log("Deployer:", deployer.address);
  console.log("Proxy:", DETERMINISTIC_DEPLOYMENT_PROXY);
  console.log("Predicted address:", predictedAddress);

  if (existingCode && existingCode !== "0x") {
    console.log("Contract already deployed at predicted address. Skipping deploy.");
    return;
  }

  const gasPrice = BigInt(await provider.send("eth_gasPrice", []));
  const nonce = await provider.getTransactionCount(deployer.address, "latest");
  const gasLimit = BigInt(process.env.AES_BACKUP_VAULT_DEPLOY_GAS_LIMIT || "2000000");

  const sentTx = await deployer.sendTransaction({
    to: DETERMINISTIC_DEPLOYMENT_PROXY,
    data: buildDeterministicDeployData(bytecode),
    gasPrice,
    nonce,
    gasLimit,
  });

  console.log("Deployment tx hash:", sentTx.hash);
  const receipt = await sentTx.wait();
  if (!receipt || receipt.status !== 1) {
    throw new Error("CREATE2 deployment transaction failed.");
  }

  const deployedCode = await provider.getCode(predictedAddress);
  if (!deployedCode || deployedCode === "0x") {
    throw new Error("Deployment mined but no bytecode found at predicted address.");
  }

  console.log("AesKeyBackupVault deployed at:", predictedAddress);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
