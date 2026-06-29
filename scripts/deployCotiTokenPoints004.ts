import { ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  if (!deployer) {
    throw new Error(
      "No deployer signer found. Set PRIVATE_KEY in your environment."
    );
  }

  const defaultAdmin =
    process.env.TPS004_ADMIN || deployer.address;
  const pauser = process.env.TPS004_PAUSER || deployer.address;
  const minter = process.env.TPS004_MINTER || deployer.address;

  console.log("Deploying CotiTokenPoints004...");
  console.log("Deployer:", deployer.address);
  console.log("Default admin:", defaultAdmin);
  console.log("Pauser:", pauser);
  console.log("Minter:", minter);

  const provider = deployer.provider;
  if (!provider) {
    throw new Error("No provider found for deployer signer.");
  }

  const gasPrice = BigInt(await provider.send("eth_gasPrice", []));
  const nonce = await provider.getTransactionCount(deployer.address, "latest");
  const gasLimit = BigInt(process.env.TPS004_DEPLOY_GAS_LIMIT || "6000000");

  const factory = await ethers.getContractFactory("CotiTokenPoints004");
  const deployTxReq = await factory.getDeployTransaction(
    defaultAdmin,
    pauser,
    minter
  );
  if (!deployTxReq.data) {
    throw new Error("Failed to build deploy transaction data.");
  }

  const sentTx = await deployer.sendTransaction({
    data: deployTxReq.data,
    gasPrice,
    nonce,
    gasLimit,
  });
  console.log("Deployment tx hash:", sentTx.hash);
  const receipt = await sentTx.wait();
  if (!receipt || !receipt.contractAddress) {
    throw new Error(
      "Deployment transaction mined but no contract address found."
    );
  }

  console.log("CotiTokenPoints004 deployed at:", receipt.contractAddress);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
