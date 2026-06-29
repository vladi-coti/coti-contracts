import fs from "fs";
import path from "path";
import { ethers } from "hardhat";

function findBuildInfo(): string {
  const dir = path.join("artifacts", "build-info");
  for (const file of fs.readdirSync(dir)) {
    if (!file.endsWith(".json")) continue;
    const fullPath = path.join(dir, file);
    const raw = fs.readFileSync(fullPath, "utf8");
    if (
      raw.includes("FixedRatioCoinDisperserUnlimitedWindow") &&
      raw.includes('"version": "0.8.20"')
    ) {
      return fullPath;
    }
  }
  throw new Error(
    "No 0.8.20 build-info found for FixedRatioCoinDisperserUnlimitedWindow. Run `npx hardhat compile` first."
  );
}

async function main() {
  const address =
    process.env.CONTRACT_ADDRESS ||
    "0x6f05f45897A3c8cBC4Cb384cB69d5425C13fbAe2";
  const pointsToken =
    process.env.POINTS_TOKEN ||
    "0x9eC8c1459B92e8f19fE160E63e169e7EFAAA4359";
  const owner =
    process.env.DISPERSER_OWNER ||
    "0x87a11daf013e02d38cabdfdbff25e0b0fa2c5fcd";

  const buildInfo = JSON.parse(fs.readFileSync(findBuildInfo(), "utf8")) as {
    input: unknown;
    solcVersion: string;
  };

  const iface = new ethers.Interface([
    "constructor(address _pointsToken, address _owner)",
  ]);
  const constructorArguments = iface
    .encodeDeploy([pointsToken, owner])
    .slice(2);

  const params = new URLSearchParams({
    apikey: "placeholder",
    module: "contract",
    action: "verifysourcecode",
    contractaddress: address,
    sourceCode: JSON.stringify(buildInfo.input),
    codeformat: "solidity-standard-json-input",
    contractname:
      "contracts/disperse/coinByRatio/FixedRatioCoinDisperserUnlimitedWindow.sol:FixedRatioCoinDisperserUnlimitedWindow",
    compilerversion: `v${buildInfo.solcVersion}+commit.a1b79de6`,
    constructorArguements: constructorArguments,
  });

  console.log("Submitting verification to Cotiscan...");
  const submit = await fetch("https://mainnet.cotiscan.io/api", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });
  const submitJson = (await submit.json()) as {
    status: string;
    message: string;
    result: string;
  };
  if (submitJson.status !== "1") {
    throw new Error(
      `Verification submit failed: ${submitJson.message} (${submitJson.result})`
    );
  }

  const guid = submitJson.result;
  console.log("Verification GUID:", guid);

  for (let i = 0; i < 30; i++) {
    await new Promise((r) => setTimeout(r, 5000));
    const statusUrl = new URL("https://mainnet.cotiscan.io/api");
    statusUrl.search = new URLSearchParams({
      apikey: "placeholder",
      module: "contract",
      action: "checkverifystatus",
      guid,
    }).toString();
    const statusRes = await fetch(statusUrl);
    const statusJson = (await statusRes.json()) as {
      status: string;
      result: string;
    };
    console.log("Status:", statusJson.result);
    if (statusJson.result.includes("Pass")) {
      console.log("Contract verified:", address);
      return;
    }
    if (
      statusJson.result.includes("Fail") ||
      statusJson.result.includes("Error")
    ) {
      throw new Error(`Verification failed: ${statusJson.result}`);
    }
  }

  throw new Error("Verification timed out while polling Cotiscan");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
