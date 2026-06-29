import fs from "fs";
import path from "path";
import { ethers } from "hardhat";

function findBuildInfo(): string {
  const dir = path.join("artifacts", "build-info");
  for (const file of fs.readdirSync(dir)) {
    if (!file.endsWith(".json")) continue;
    const fullPath = path.join(dir, file);
    const buildInfo = JSON.parse(fs.readFileSync(fullPath, "utf8")) as {
      solcVersion: string;
    };
    const raw = fs.readFileSync(fullPath, "utf8");
    if (
      raw.includes("CotiTokenPoints004") &&
      buildInfo.solcVersion === "0.8.20"
    ) {
      return fullPath;
    }
  }
  throw new Error(
    "No 0.8.20 build-info found for CotiTokenPoints004. Run `npx hardhat compile` first."
  );
}

async function main() {
  const address =
    process.env.CONTRACT_ADDRESS ||
    "0x3F577B64E5CE5F2d00607770368d623cECc4FF7D";
  const defaultAdmin =
    process.env.TPS004_ADMIN ||
    "0x0BF9C15CbD9f0fac9fc6ab90F0603e89818489bd";
  const pauser =
    process.env.TPS004_PAUSER ||
    "0x0BF9C15CbD9f0fac9fc6ab90F0603e89818489bd";
  const minter =
    process.env.TPS004_MINTER ||
    "0xE16eD4D157D4AdB562a7a73D28CBA750Ac48d735";

  const buildInfo = JSON.parse(fs.readFileSync(findBuildInfo(), "utf8")) as {
    input: unknown;
    solcVersion: string;
    solcLongVersion?: string;
  };

  const commit =
    buildInfo.solcLongVersion?.split("+commit.")[1] ?? "a1b79de6";

  const iface = new ethers.Interface([
    "constructor(address defaultAdmin, address pauser, address minter)",
  ]);
  const constructorArguments = iface
    .encodeDeploy([defaultAdmin, pauser, minter])
    .slice(2);

  const params = new URLSearchParams({
    apikey: "placeholder",
    module: "contract",
    action: "verifysourcecode",
    contractaddress: address,
    sourceCode: JSON.stringify(buildInfo.input),
    codeformat: "solidity-standard-json-input",
    contractname:
      "contracts/token/points/CotiTokenPoints004.sol:CotiTokenPoints004",
    compilerversion: `v${buildInfo.solcVersion}+commit.${commit}`,
    constructorArguements: constructorArguments,
  });

  console.log("Submitting verification to Cotiscan...");
  console.log("Contract:", address);
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
