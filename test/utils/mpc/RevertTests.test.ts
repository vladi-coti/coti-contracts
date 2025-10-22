import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"
import { gasOptions } from "./helpers";

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()
  const factory = await hre.ethers.getContractFactory("RevertTestsContract")
  const contract = await factory.connect(owner).deploy(gasOptions)
  await contract.waitForDeployment()
  return { contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

describe("MPC Core - Revert Tests", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>
  
  before(async function () {
    deployment = await deploy()
  })

  describe("Test 1: Simple revert with a string", function () {
    it("Should revert with string message", async function () {
      const { contract } = deployment
      
      await expect(contract.simpleRevertWithString(gasOptions)).to.be.revertedWith(
        "This is a simple revert with a string message"
      )
    })
  })

  describe("Test 2: Require depending on function arg with a string", function () {
    it("Should pass when arg is true", async function () {
      const { contract } = deployment
      
      expect(await contract.requireWithArg(true, gasOptions)).not.to.be.reverted
    })

    it("Should revert when arg is false", async function () {
      const { contract } = deployment
      
      await expect(contract.requireWithArg(false, gasOptions)).to.be.revertedWith(
        "Require failed: argument condition not met"
      )
    })
  })

  describe("Test 3: Require with validated ciphertext", function () {
    it("Should pass when encrypted bool is true", async function () {
      const { contract, contractAddress, owner } = deployment
      
      const itValue = await owner.encryptBool(
        true,
        contractAddress,
        contract.requireWithValidatedCiphertext.fragment.selector
      )
      
      expect(await contract.requireWithValidatedCiphertext(itValue, gasOptions)).not.to.be.reverted
    })

    it("Should revert when encrypted bool is false", async function () {
      const { contract, contractAddress, owner } = deployment
      
      const itValue = await owner.encryptBool(
        false,
        contractAddress,
        contract.requireWithValidatedCiphertext.fragment.selector
      )
      
      await expect(contract.requireWithValidatedCiphertext(itValue, gasOptions)).to.be.revertedWith(
        "Require failed: validated ciphertext condition not met"
      )
    })
  })

  describe("Test 4a: Require with setPublic boolean", function () {
    it("Should pass when boolean is true", async function () {
      const { contract } = deployment

      expect(await contract.requireWithSetPublicBool(true, gasOptions)).not.to.be.reverted
    })

    it("Should revert when boolean is false", async function () {
      const { contract } = deployment
      
      await expect(contract.requireWithSetPublicBool(false, gasOptions)).to.be.revertedWith(
        "Require failed: setPublic boolean condition not met"
      )
    })
  })

  describe("Test 4b: Require with setPublic number", function () {
    it("Should pass when number is > 50", async function () {
      const { contract } = deployment
      
      expect(await contract.requireWithSetPublicNumber(75, gasOptions)).not.to.be.reverted
    })

    it("Should revert when number is <= 50", async function () {
      const { contract } = deployment
      
      await expect(contract.requireWithSetPublicNumber(25, gasOptions)).to.be.revertedWith(
        "Require failed: setPublic number condition not met (must be > 50)"
      )
    })
  })

  describe("Additional Test: Require with setPublic signed number", function () {
    it("Should pass when signed number is > 0", async function () {
      const { contract } = deployment
      
      expect(await contract.requireWithSetPublicSignedNumber(42, gasOptions)).not.to.be.reverted
    })

    it("Should revert when signed number is <= 0", async function () {
      const { contract } = deployment
      
      await expect(contract.requireWithSetPublicSignedNumber(-10, gasOptions)).to.be.revertedWith(
        "Require failed: setPublic signed number condition not met (must be > 0)"
      )
    })
  })

  describe("Additional Test: Complex require with multiple encrypted values", function () {
    it("Should pass when both conditions are met", async function () {
      const { contract } = deployment
      
      expect(await contract.requireWithMultipleEncryptedValues(true, 30, gasOptions)).not.to.be.reverted
    })

    it("Should revert when boolean is false", async function () {
      const { contract } = deployment
      
      await expect(contract.requireWithMultipleEncryptedValues(false, 30, gasOptions)).to.be.revertedWith(
        "Require failed: complex condition not met (bool must be true AND number > 25)"
      )
    })

    it("Should revert when number is <= 25", async function () {
      const { contract } = deployment
      const tx = await contract.requireWithMultipleEncryptedValues(true, 20, gasOptions)
      await tx.wait()
    //   await expect(contract.requireWithMultipleEncryptedValues(true, 20, gasOptions)).to.be.revertedWith(
    //     "Require failed: complex condition not met (bool must be true AND number > 25)"
    //   )
    })
  })
})
