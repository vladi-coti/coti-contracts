import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../utils/accounts"
import { Wallet } from "@coti-io/coti-ethers"

const gasLimit = 12000000

// Proxy deployment helper function
async function deployProxy(ethers: any, deployer: any) {
  const Factory = await ethers.getContractFactory("ProxyTestMock")

  const gasOptions = {
    gasLimit: 5000000,
    gasPrice: 1000000000,
  }

  // 1. Deploy the implementation contract
  console.log("Deploying implementation...")
  const implementation = await Factory.connect(deployer).deploy(gasOptions)
  await implementation.waitForDeployment()
  const implementationAddress = await implementation.getAddress()
  console.log("Implementation deployed to:", implementationAddress)

  // 2. Deploy ProxyAdmin using artifacts
  console.log("Deploying ProxyAdmin...")
  const proxyAdminArtifact = require("@openzeppelin/contracts/build/contracts/ProxyAdmin.json")
  const ProxyAdminFactory = new ethers.ContractFactory(proxyAdminArtifact.abi, proxyAdminArtifact.bytecode, deployer)
  const proxyAdmin = await ProxyAdminFactory.deploy(gasOptions)
  await proxyAdmin.waitForDeployment()
  const proxyAdminAddress = await proxyAdmin.getAddress()
  console.log("ProxyAdmin deployed to:", proxyAdminAddress)

  // 3. Deploy TransparentUpgradeableProxy using artifacts
  console.log("Deploying TransparentUpgradeableProxy...")
  const transparentProxyArtifact = require("@openzeppelin/contracts/build/contracts/TransparentUpgradeableProxy.json")
  const TransparentUpgradeableProxyFactory = new ethers.ContractFactory(
    transparentProxyArtifact.abi,
    transparentProxyArtifact.bytecode,
    deployer
  )
  const proxy = await TransparentUpgradeableProxyFactory.deploy(
    implementationAddress,
    proxyAdminAddress,
    "0x",
    gasOptions
  )
  await proxy.waitForDeployment()
  const proxyAddress = await proxy.getAddress()
  console.log("TransparentUpgradeableProxy deployed to:", proxyAddress)

  // 4. Attach the implementation ABI to the proxy address
  const proxyContract = Factory.attach(proxyAddress)

  return { contract: proxyContract, implementationAddress, proxyAdminAddress, proxyAddress }
}

// Direct deployment
async function deployDirect() {
  const [owner, otherAccount] = await setupAccounts()

  const factory = await hre.ethers.getContractFactory("ProxyTestMock")
  const contract = await factory.connect(owner).deploy({ gasLimit })
  await contract.waitForDeployment()

  return {
    contract,
    contractAddress: await contract.getAddress(),
    owner,
    otherAccount,
  }
}

describe("ProxyTestMock - Direct Deployment", function () {
  let deployment: Awaited<ReturnType<typeof deployDirect>>
  let userWallet: Wallet

  before(async function () {
    deployment = await deployDirect()
    // Use the first account as userWallet
    userWallet = deployment.owner
  })

  it("Should deploy the contract directly", async function () {
    const { contract, contractAddress } = deployment

    expect(contractAddress).to.not.equal("0x0000000000000000000000000000000000000000")
    expect(await contract.getAddress()).to.equal(contractAddress)
  })

  it("Should validate encrypted parameter and emit PrivateParamsTest event", async function () {
    const { contract } = deployment

    // Test value to encrypt
    const testValue = BigInt("12345678901234567890")

    // Get contract address and selector for encryption
    const contractAddress = await contract.getAddress()
    const selector = (contract as any).interface.getFunction("validateSingleParam").selector

    // Encrypt the value using userWallet
    const encryptedParam = await userWallet.encryptUint256(testValue, contractAddress, selector)

    // Call the function and expect it to emit the event
    const tx = await contract.connect(userWallet).validateSingleParam(encryptedParam)
    const receipt = await tx.wait()

    expect(receipt).to.not.be.null
    await expect(tx).to.emit(contract, "PrivateParamsTest")
  })
})

describe("ProxyTestMock - Proxy Deployment", function () {
  let proxy: any
  let implementationAddress: string
  let proxyAddress: string
  let userWallet: Wallet

  before(async function () {
    // Setup accounts
    const accounts = await setupAccounts()
    userWallet = accounts[0]

    // Deploy the contract using a transparent proxy
    ;({ contract:proxy, implementationAddress, proxyAddress } = await deployProxy(hre.ethers, userWallet))
  })

  it("Should deploy the contract through proxy", async function () {
    expect(await proxy.getAddress()).to.not.equal("0x0000000000000000000000000000000000000000")
  })

  it("Should work through proxy call - proxy address", async function () {
    // Test value to encrypt
    const testValue = BigInt("98765432109876543210")

    // Get contract address and selector for encryption
    const contractAddress = proxyAddress
    const selector = proxy.interface.getFunction("validateSingleParam").selector

    // Encrypt the value using userWallet
    const encryptedParam = await userWallet.encryptUint256(testValue, contractAddress, selector)

    // Call the function through proxy and expect it to emit the event
    const tx = await proxy.connect(userWallet).validateSingleParam(encryptedParam)
    const receipt = await tx.wait()

    expect(receipt).to.not.be.null
    await expect(tx).to.emit(proxy, "PrivateParamsTest")
  })

  it("Should work through proxy call - implementation address", async function () {
    // Test value to encrypt
    const testValue = BigInt("98765432109876543210")

    // Get contract address and selector for encryption
    const contractAddress = implementationAddress
    const selector = proxy.interface.getFunction("validateSingleParam").selector

    // Encrypt the value using userWallet
    const encryptedParam = await userWallet.encryptUint256(testValue, contractAddress, selector)

    // Call the function through proxy and expect it to emit the event
    const tx = await proxy.connect(userWallet).validateSingleParam(encryptedParam)
    const receipt = await tx.wait()

    expect(receipt).to.not.be.null
    await expect(tx).to.emit(proxy, "PrivateParamsTest")
  })
})
