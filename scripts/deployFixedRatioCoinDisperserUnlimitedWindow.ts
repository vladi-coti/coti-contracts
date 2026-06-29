import { ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  if (!deployer) {
    throw new Error(
      "No deployer signer found. Set PRIVATE_KEY in your environment."
    );
  }

  const pointsToken =
    process.env.POINTS_TOKEN ||
    "0x9eC8c1459B92e8f19fE160E63e169e7EFAAA4359";
  const owner =
    process.env.DISPERSER_OWNER ||
    "0x87a11daf013e02d38cabdfdbff25e0b0fa2c5fcd";

  console.log("Deploying FixedRatioCoinDisperserUnlimitedWindow...");
  console.log("Deployer:", deployer.address);
  console.log("Points token:", pointsToken);
  console.log("Owner:", owner);

  const provider = deployer.provider;
  if (!provider) {
    throw new Error("No provider found for deployer signer.");
  }

  const gasPrice = BigInt(await provider.send("eth_gasPrice", []));
  const nonce = await provider.getTransactionCount(deployer.address, "latest");
  const gasLimit = BigInt(
    process.env.DISPERSER_DEPLOY_GAS_LIMIT || "8000000"
  );

  const factory = await ethers.getContractFactory(
    "FixedRatioCoinDisperserUnlimitedWindow"
  );
  const deployTxReq = await factory.getDeployTransaction(
    pointsToken,
    owner
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

  console.log(
    "FixedRatioCoinDisperserUnlimitedWindow deployed at:",
    receipt.contractAddress
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
