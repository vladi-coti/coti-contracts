import { run } from "hardhat";
import {
  getAesKeyBackupVaultBytecode,
  predictAesKeyBackupVaultAddress,
} from "./aesKeyBackupVaultCreate2";

async function main() {
  const bytecode = await getAesKeyBackupVaultBytecode();
  const predictedAddress = predictAesKeyBackupVaultAddress(bytecode);
  const address = process.env.CONTRACT_ADDRESS || predictedAddress;

  console.log("Verifying AesKeyBackupVault at:", address);

  await run("verify:verify", {
    address,
    constructorArguments: [],
  });
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
