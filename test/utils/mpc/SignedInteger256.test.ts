import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"
import { itUint } from "@coti-io/coti-ethers"

const gasLimit = 12000000

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const factory = await hre.ethers.getContractFactory("SignedInt256TestsContract")
  const contract = await factory.connect(owner).deploy({ gasLimit })
  await contract.waitForDeployment()

  return { contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

describe("MPC Core - signed 256-bit integers", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>

  before(async function () {
    deployment = await deploy()
  })

  describe("Validating encrypted signed 256-bit integers", function () {
    it("Should validate positive signed 256-bit integers", async function () {
      const { contract, contractAddress, owner } = deployment

      const testValue = 1234567890123456789012345678901234567890n
      const itValue = (await owner.encryptValue(
        testValue,
        contractAddress,
        contract.validateCiphertextTest.fragment.selector
      )) as itUint

      await (await contract.validateCiphertextTest(itValue)).wait()

      const decryptedInt = await contract.validateResult()

      expect(decryptedInt).to.equal(testValue)
    })

    it("Should validate negative signed 256-bit integers", async function () {
      const { contract, contractAddress, owner } = deployment

      const testValue = -987654321098765432109876543210987654321n
      const itValue = (await owner.encryptValue(
        testValue,
        contractAddress,
        contract.validateCiphertextTest.fragment.selector
      )) as itUint

      await (await contract.validateCiphertextTest(itValue)).wait()

      const decryptedInt = await contract.validateResult()

      expect(decryptedInt).to.equal(testValue)
    })
  })

  describe("Adding signed 256-bit integers", function () {
    it("Should encrypt, add and decrypt two positive signed 256-bit integers", async function () {
      const { contract } = deployment

      await (
        await contract.addTest(1000000000000000000000000000000000000000n, 2000000000000000000000000000000000000000n)
      ).wait()

      const decryptedInt = await contract.addResult()

      expect(decryptedInt).to.equal(3000000000000000000000000000000000000000n)
    })

    it("Should encrypt, add and decrypt two negative signed 256-bit integers", async function () {
      const { contract } = deployment

      await (
        await contract.addTest(-1000000000000000000000000000000000000000n, -2000000000000000000000000000000000000000n)
      ).wait()

      const decryptedInt = await contract.addResult()

      expect(decryptedInt).to.equal(-3000000000000000000000000000000000000000n)
    })

    it("Should encrypt, add and decrypt a positive and negative signed 256-bit integer", async function () {
      const { contract } = deployment

      await (
        await contract.addTest(5000000000000000000000000000000000000000n, -3000000000000000000000000000000000000000n)
      ).wait()

      const decryptedInt = await contract.addResult()

      expect(decryptedInt).to.equal(2000000000000000000000000000000000000000n)
    })

    it("Should encrypt, add and decrypt a negative and positive signed 256-bit integer", async function () {
      const { contract } = deployment

      await (
        await contract.addTest(-8000000000000000000000000000000000000000n, 3000000000000000000000000000000000000000n)
      ).wait()

      const decryptedInt = await contract.addResult()

      expect(decryptedInt).to.equal(-5000000000000000000000000000000000000000n)
    })
  })

  // ... Repeat for subTest, mulTest, divTest, andTest, orTest, xorTest, eqTest, neTest, gtTest, ltTest, geTest, leTest, offBoardTest, onBoardTest ...
})
