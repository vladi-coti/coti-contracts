import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../utils/accounts"
import { EventLog, Wallet } from "@coti-io/coti-ethers"

const gasOptions = {
  gasLimit: 5000000,
  gasPrice: 1000000000,
}

// Proxy deployment helper function
async function deployProxy(ethers: any, deployer: Wallet) {
  const Factory = await ethers.getContractFactory("ProxyTestMock")

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
  const proxyContract = Factory.attach(proxyAddress).connect(deployer)

  return { contract: proxyContract, implementationAddress, proxyAdminAddress, proxyAddress }
}

// Direct deployment
async function deployDirect(deployer: Wallet) {
  const factory = await hre.ethers.getContractFactory("ProxyTestMock")
  const contract = await factory.connect(deployer).deploy(gasOptions)
  await contract.waitForDeployment()

  return {
    contract,
    contractAddress: await contract.getAddress(),
  }
}

describe("ProxyTestMock - Direct Deployment", function () {
  let deployment: Awaited<ReturnType<typeof deployDirect>>
  let userWallet: Wallet

  before(async function () {
    const accounts = await setupAccounts()
    userWallet = accounts[1]
    deployment = await deployDirect(userWallet)

    console.log(`User wallet address: ${userWallet.address}`)
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
    console.log("selector", selector)
    console.log("contractAddress", contractAddress)

    // Encrypt the value using userWallet
    const encryptedParam = await userWallet.encryptUint256(testValue, contractAddress, selector)

    // Call the function and expect it to emit the event
    const tx = await contract.connect(userWallet).validateSingleParam(encryptedParam, gasOptions)
    const receipt = await tx.wait()

    expect(receipt).to.not.be.null

    // Expect the MsgSender event to be emitted and be the userWallet address
    await expect(tx).to.emit(contract, "MsgSender").withArgs(userWallet.address)
    await expect(tx).to.emit(contract, "Origin").withArgs(userWallet.address)

    if (receipt?.logs) {
      const params = receipt.logs.find((log: any): log is EventLog => {
        return (log as EventLog).eventName === "MsgSender"
      })
      const eventMsgSender = params && "args" in params ? params.args[0] : null
      console.log(`MsgSender event emitted with address: ${eventMsgSender}`)
    }

    if (receipt?.logs) {
      const params = receipt.logs.find((log: any): log is EventLog => {
        return (log as EventLog).eventName === "Origin"
      })
      const eventOrigin = params && "args" in params ? params.args[0] : null
      console.log(`Origin event emitted with address: ${eventOrigin}`)
    }

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
    userWallet = accounts[1]

    // Deploy the contract using a transparent proxy
    ;({ contract: proxy, implementationAddress, proxyAddress } = await deployProxy(hre.ethers, userWallet))

    console.log(`User wallet address: ${userWallet.address}`)
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
    console.log("selector", selector)
    console.log("contractAddress", contractAddress)

    // Encrypt the value using userWallet
    const encryptedParam = await userWallet.encryptUint256(testValue, contractAddress, selector)

    // Call the function through proxy and expect it to emit the event
    const tx = await proxy.connect(userWallet).validateSingleParam(encryptedParam, gasOptions)
    const receipt = await tx.wait()

    expect(receipt).to.not.be.null

    // Expect the MsgSender event to be emitted and be the userWallet address
    await expect(tx).to.emit(proxy, "MsgSender").withArgs(userWallet.address)
    await expect(tx).to.emit(proxy, "Origin").withArgs(userWallet.address)

    if (receipt?.logs) {
      const params = receipt.logs.find((log: any): log is EventLog => {
        return (log as EventLog).eventName === "MsgSender"
      })
      const eventMsgSender = params && "args" in params ? params.args[0] : null
      console.log(`MsgSender event emitted with address: ${eventMsgSender}`)
    }

    if (receipt?.logs) {
      const params = receipt.logs.find((log: any): log is EventLog => {
        return (log as EventLog).eventName === "Origin"
      })
      const eventOrigin = params && "args" in params ? params.args[0] : null
      console.log(`Origin event emitted with address: ${eventOrigin}`)
    }

    await expect(tx).to.emit(proxy, "PrivateParamsTest")
  })

  it("Should work through proxy call - implementation address", async function () {
    // Test value to encrypt
    const testValue = BigInt("98765432109876543210")

    // Get contract address and selector for encryption
    const contractAddress = implementationAddress
    const selector = proxy.interface.getFunction("validateSingleParam").selector
    console.log("selector", selector)
    console.log("contractAddress", contractAddress)

    // Encrypt the value using userWallet
    const encryptedParam = await userWallet.encryptUint256(testValue, contractAddress, selector)

    // Call the function through proxy and expect it to emit the event
    const tx = await proxy.connect(userWallet).validateSingleParam(encryptedParam, gasOptions)
    const receipt = await tx.wait()

    expect(receipt).to.not.be.null

    // Expect the MsgSender event to be emitted and be the userWallet address
    await expect(tx).to.emit(proxy, "MsgSender").withArgs(userWallet.address)
    await expect(tx).to.emit(proxy, "Origin").withArgs(userWallet.address)

    if (receipt?.logs) {
      const params = receipt.logs.find((log: any): log is EventLog => {
        return (log as EventLog).eventName === "MsgSender"
      })
      const eventMsgSender = params && "args" in params ? params.args[0] : null
      console.log(`MsgSender event emitted with address: ${eventMsgSender}`)
    }

    if (receipt?.logs) {
      const params = receipt.logs.find((log: any): log is EventLog => {
        return (log as EventLog).eventName === "Origin"
      })
      const eventOrigin = params && "args" in params ? params.args[0] : null
      console.log(`Origin event emitted with address: ${eventOrigin}`)
    }

    await expect(tx).to.emit(proxy, "PrivateParamsTest")
  })

  it("Should work through proxy call - user wallet address", async function () {
    // Test value to encrypt
    const testValue = BigInt("98765432109876543210")

    // Get contract address and selector for encryption
    const contractAddress = userWallet.address
    const selector = proxy.interface.getFunction("validateSingleParam").selector
    console.log("selector", selector)
    console.log("contractAddress", contractAddress)

    // Encrypt the value using userWallet
    const encryptedParam = await userWallet.encryptUint256(testValue, contractAddress, selector)

    // Call the function through proxy and expect it to emit the event
    const tx = await proxy.connect(userWallet).validateSingleParam(encryptedParam, gasOptions)
    const receipt = await tx.wait()

    expect(receipt).to.not.be.null

    // Expect the MsgSender event to be emitted and be the userWallet address
    await expect(tx).to.emit(proxy, "MsgSender").withArgs(userWallet.address)
    await expect(tx).to.emit(proxy, "Origin").withArgs(userWallet.address)

    if (receipt?.logs) {
      const params = receipt.logs.find((log: any): log is EventLog => {
        return (log as EventLog).eventName === "MsgSender"
      })
      const eventMsgSender = params && "args" in params ? params.args[0] : null
      console.log(`MsgSender event emitted with address: ${eventMsgSender}`)
    }

    if (receipt?.logs) {
      const params = receipt.logs.find((log: any): log is EventLog => {
        return (log as EventLog).eventName === "Origin"
      })
      const eventOrigin = params && "args" in params ? params.args[0] : null
      console.log(`Origin event emitted with address: ${eventOrigin}`)
    }

    await expect(tx).to.emit(proxy, "PrivateParamsTest")
  })
})
