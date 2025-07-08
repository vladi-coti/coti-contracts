import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"

const gasLimit = 12000000

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const factory = await hre.ethers.getContractFactory("SignedInt128TestsContract")
  const contract = await factory.connect(owner).deploy({ gasLimit })
  await contract.waitForDeployment()

  return { contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

describe("MPC Core - signed 128-bit integers", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>

  before(async function () {
    deployment = await deploy()
  })

  describe("Validating encrypted signed 128-bit integers", function () {
    it("Should validate positive signed 128-bit integers", async function () {
      const { contract, contractAddress, owner } = deployment

      const testValue = 123456789012345n
      const itValue = await owner.encryptInt128(
        testValue,
        contractAddress,
        contract.validateCiphertextTest.fragment.selector
      )

      await (await contract.validateCiphertextTest(itValue)).wait()

      const decryptedInt = await contract.validateResult()

      expect(decryptedInt).to.equal(testValue)
    })

    it("Should validate negative signed 128-bit integers", async function () {
      const { contract, contractAddress, owner } = deployment

      const testValue = -987654321098765n
      const itValue = await owner.encryptInt128(
        testValue,
        contractAddress,
        contract.validateCiphertextTest.fragment.selector
      )

      await (await contract.validateCiphertextTest(itValue)).wait()

      const decryptedInt = await contract.validateResult()

      expect(decryptedInt).to.equal(testValue)
    })
  })

  describe("Adding signed 128-bit integers", function () {
    it("Should encrypt, add and decrypt two positive signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.addTest(1000000000n, 2000000000n)).wait()

      const decryptedInt = await contract.addResult()

      expect(decryptedInt).to.equal(3000000000n)
    })

    it("Should encrypt, add and decrypt two negative signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.addTest(-1000000000n, -2000000000n)).wait()

      const decryptedInt = await contract.addResult()

      expect(decryptedInt).to.equal(-3000000000n)
    })

    it("Should encrypt, add and decrypt a positive and negative signed 128-bit integer", async function () {
      const { contract } = deployment

      await (await contract.addTest(5000000000n, -3000000000n)).wait()

      const decryptedInt = await contract.addResult()

      expect(decryptedInt).to.equal(2000000000n)
    })

    it("Should encrypt, add and decrypt a negative and positive signed 128-bit integer", async function () {
      const { contract } = deployment

      await (await contract.addTest(-8000000000n, 3000000000n)).wait()

      const decryptedInt = await contract.addResult()

      expect(decryptedInt).to.equal(-5000000000n)
    })
  })

  describe("Subtracting signed 128-bit integers", function () {
    it("Should encrypt, subtract and decrypt two positive signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.subTest(5000000000n, 2000000000n)).wait()

      const decryptedInt = await contract.subResult()

      expect(decryptedInt).to.equal(3000000000n)
    })

    it("Should encrypt, subtract and decrypt two negative signed 128-bit integers", async function () {
      // Deploy fresh contract to avoid state pollution
      const freshDeployment = await deploy()
      const { contract } = freshDeployment

      await (await contract.subTest(-5000000000n, -2000000000n)).wait()

      const decryptedInt = await contract.subResult()

      expect(decryptedInt).to.equal(-3000000000n)
    })

    it("Should encrypt, subtract and decrypt a positive and negative signed 128-bit integer", async function () {
      // Deploy fresh contract to avoid state pollution
      const freshDeployment = await deploy()
      const { contract } = freshDeployment

      await (await contract.subTest(5000000000n, -3000000000n)).wait()

      const decryptedInt = await contract.subResult()

      expect(decryptedInt).to.equal(8000000000n)
    })

    it("Should encrypt, subtract and decrypt a negative and positive signed 128-bit integer", async function () {
      // Deploy fresh contract to avoid state pollution
      const freshDeployment = await deploy()
      const { contract } = freshDeployment

      await (await contract.subTest(-8000000000n, 3000000000n)).wait()

      const decryptedInt = await contract.subResult()

      expect(decryptedInt).to.equal(-11000000000n)
    })
  })

  describe("Multiplying signed 128-bit integers", function () {
    it("Should encrypt, multiply and decrypt two positive signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.mulTest(1000000n, 2000n)).wait()

      const decryptedInt = await contract.mulResult()

      expect(decryptedInt).to.equal(2000000000n)
    })

    it("Should encrypt, multiply and decrypt two negative signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.mulTest(-1000000n, -3000n)).wait()

      const decryptedInt = await contract.mulResult()

      expect(decryptedInt).to.equal(3000000000n)
    })

    it("Should encrypt, multiply and decrypt a positive and negative signed 128-bit integer", async function () {
      const { contract } = deployment

      await (await contract.mulTest(2000000n, -1500n)).wait()

      const decryptedInt = await contract.mulResult()

      expect(decryptedInt).to.equal(-3000000000n)
    })

    it("Should encrypt, multiply and decrypt a negative and positive signed 128-bit integer", async function () {
      const { contract } = deployment

      await (await contract.mulTest(-2000000n, 1500n)).wait()

      const decryptedInt = await contract.mulResult()

      expect(decryptedInt).to.equal(-3000000000n)
    })
  })

  describe("Dividing signed 128-bit integers", function () {
    it("Should encrypt, divide and decrypt two positive signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.divTest(6000000000n, 2000000000n)).wait()

      const decryptedInt = await contract.divResult()

      expect(decryptedInt).to.equal(3n)
    })

    it("Should encrypt, divide and decrypt two negative signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.divTest(-9000000000n, -3000000000n)).wait()

      const decryptedInt = await contract.divResult()

      expect(decryptedInt).to.equal(3n)
    })

    it("Should encrypt, divide and decrypt a positive and negative signed 128-bit integer", async function () {
      const { contract } = deployment

      await (await contract.divTest(8000000000n, -2000000000n)).wait()

      const decryptedInt = await contract.divResult()

      expect(decryptedInt).to.equal(-4n)
    })

    it("Should encrypt, divide and decrypt a negative and positive signed 128-bit integer", async function () {
      const { contract } = deployment

      await (await contract.divTest(-12000000000n, 3000000000n)).wait()

      const decryptedInt = await contract.divResult()

      expect(decryptedInt).to.equal(-4n)
    })
  })

  describe("AND signed 128-bit integers", function () {
    it("Should encrypt, AND and decrypt two positive signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.andTest(0xFFFFFFFn, 0x123456789n)).wait()

      const decryptedInt = await contract.andResult()

      expect(decryptedInt).to.equal(0x23456789n)
    })

    it("Should encrypt, AND and decrypt two negative signed 128-bit integers", async function () {
      // Deploy fresh contract to avoid state pollution
      const freshDeployment = await deploy()
      const { contract } = freshDeployment

      await (await contract.andTest(-1n, -1n)).wait()

      const decryptedInt = await contract.andResult()

      expect(decryptedInt).to.equal(-1n)
    })

    it("Should encrypt, AND and decrypt a positive and negative signed 128-bit integer", async function () {
      const { contract } = deployment

      await (await contract.andTest(0xFFFFFFFFn, -1n)).wait()

      const decryptedInt = await contract.andResult()

      expect(decryptedInt).to.equal(0xFFFFFFFFn)
    })

    it("Should encrypt, AND and decrypt a negative and positive signed 128-bit integer", async function () {
      // Deploy fresh contract to avoid state pollution
      const freshDeployment = await deploy()
      const { contract } = freshDeployment

      await (await contract.andTest(-2n, 1n)).wait()

      const decryptedInt = await contract.andResult()

      expect(decryptedInt).to.equal(0n)
    })
  })

  describe("OR signed 128-bit integers", function () {
    it("Should encrypt, OR and decrypt two positive signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.orTest(0xF0F0F0F0n, 0x0F0F0F0Fn)).wait()

      const decryptedInt = await contract.orResult()

      expect(decryptedInt).to.equal(0xFFFFFFFFn)
    })

    it("Should encrypt, OR and decrypt two negative signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.orTest(-1n, -1n)).wait()

      const decryptedInt = await contract.orResult()

      expect(decryptedInt).to.equal(-1n)
    })

    it("Should encrypt, OR and decrypt a positive and negative signed 128-bit integer", async function () {
      const { contract } = deployment

      await (await contract.orTest(1n, -1n)).wait()

      const decryptedInt = await contract.orResult()

      expect(decryptedInt).to.equal(-1n)
    })

    it("Should encrypt, OR and decrypt a negative and positive signed 128-bit integer", async function () {
      const { contract } = deployment

      await (await contract.orTest(-2n, 1n)).wait()

      const decryptedInt = await contract.orResult()

      expect(decryptedInt).to.equal(-1n)
    })
  })

  describe("XOR signed 128-bit integers", function () {
    it("Should encrypt, XOR and decrypt two positive signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.xorTest(0xAAAAAAAAn, 0x55555555n)).wait()

      const decryptedInt = await contract.xorResult()

      expect(decryptedInt).to.equal(0xFFFFFFFFn)
    })

    it("Should encrypt, XOR and decrypt two negative signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.xorTest(-1n, -1n)).wait()

      const decryptedInt = await contract.xorResult()

      expect(decryptedInt).to.equal(0n)
    })

    it("Should encrypt, XOR and decrypt a positive and negative signed 128-bit integer", async function () {
      const { contract } = deployment

      await (await contract.xorTest(1n, -1n)).wait()

      const decryptedInt = await contract.xorResult()

      expect(decryptedInt).to.equal(-2n)
    })

    it("Should encrypt, XOR and decrypt a negative and positive signed 128-bit integer", async function () {
      const { contract } = deployment

      await (await contract.xorTest(-2n, 1n)).wait()

      const decryptedInt = await contract.xorResult()

      expect(decryptedInt).to.equal(-1n)
    })
  })

  describe("EQ signed 128-bit integers", function () {
    it("Should encrypt, EQ and decrypt two equal positive signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.eqTest(123456789012345n, 123456789012345n)).wait()

      const decryptedInt = await contract.eqResult()

      expect(decryptedInt).to.equal(true)
    })

    it("Should encrypt, EQ and decrypt two equal negative signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.eqTest(-123456789012345n, -123456789012345n)).wait()

      const decryptedInt = await contract.eqResult()

      expect(decryptedInt).to.equal(true)
    })

    it("Should encrypt, EQ and decrypt two different signed 128-bit integers", async function () {
      // Deploy fresh contract to avoid state pollution
      const freshDeployment = await deploy()
      const { contract } = freshDeployment

      await (await contract.eqTest(123456789012345n, -123456789012345n)).wait()

      const decryptedInt = await contract.eqResult()

      expect(decryptedInt).to.equal(false)
    })
  })

  describe("NE signed 128-bit integers", function () {
    it("Should encrypt, NE and decrypt two equal positive signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.neTest(123456789012345n, 123456789012345n)).wait()

      const decryptedInt = await contract.neResult()

      expect(decryptedInt).to.equal(false)
    })

    it("Should encrypt, NE and decrypt two different signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.neTest(123456789012345n, -123456789012345n)).wait()

      const decryptedInt = await contract.neResult()

      expect(decryptedInt).to.equal(true)
    })
  })

  describe("GT signed 128-bit integers", function () {
    it("Should encrypt, GT and decrypt positive signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.gtTest(5000000000n, 3000000000n)).wait()

      const decryptedInt = await contract.gtResult()

      expect(decryptedInt).to.equal(true)
    })

    it("Should encrypt, GT and decrypt negative signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.gtTest(-3000000000n, -5000000000n)).wait()

      const decryptedInt = await contract.gtResult()

      expect(decryptedInt).to.equal(true)
    })

    it("Should encrypt, GT and decrypt when first is smaller", async function () {
      const { contract } = deployment

      await (await contract.gtTest(3000000000n, 5000000000n)).wait()

      const decryptedInt = await contract.gtResult()

      expect(decryptedInt).to.equal(false)
    })
  })

  describe("LT signed 128-bit integers", function () {
    it("Should encrypt, LT and decrypt positive signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.ltTest(3000000000n, 5000000000n)).wait()

      const decryptedInt = await contract.ltResult()

      expect(decryptedInt).to.equal(true)
    })

    it("Should encrypt, LT and decrypt negative signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.ltTest(-5000000000n, -3000000000n)).wait()

      const decryptedInt = await contract.ltResult()

      expect(decryptedInt).to.equal(true)
    })

    it("Should encrypt, LT and decrypt when first is larger", async function () {
      const { contract } = deployment

      await (await contract.ltTest(5000000000n, 3000000000n)).wait()

      const decryptedInt = await contract.ltResult()

      expect(decryptedInt).to.equal(false)
    })
  })

  describe("GE signed 128-bit integers", function () {
    it("Should encrypt, GE and decrypt when first is greater", async function () {
      const { contract } = deployment

      await (await contract.geTest(5000000000n, 3000000000n)).wait()

      const decryptedInt = await contract.geResult()

      expect(decryptedInt).to.equal(true)
    })

    it("Should encrypt, GE and decrypt when values are equal", async function () {
      const { contract } = deployment

      await (await contract.geTest(5000000000n, 5000000000n)).wait()

      const decryptedInt = await contract.geResult()

      expect(decryptedInt).to.equal(true)
    })

    it("Should encrypt, GE and decrypt when first is smaller", async function () {
      const { contract } = deployment

      await (await contract.geTest(3000000000n, 5000000000n)).wait()

      const decryptedInt = await contract.geResult()

      expect(decryptedInt).to.equal(false)
    })
  })

  describe("LE signed 128-bit integers", function () {
    it("Should encrypt, LE and decrypt when first is smaller", async function () {
      const { contract } = deployment

      await (await contract.leTest(3000000000n, 5000000000n)).wait()

      const decryptedInt = await contract.leResult()

      expect(decryptedInt).to.equal(true)
    })

    it("Should encrypt, LE and decrypt when values are equal", async function () {
      const { contract } = deployment

      await (await contract.leTest(5000000000n, 5000000000n)).wait()

      const decryptedInt = await contract.leResult()

      expect(decryptedInt).to.equal(true)
    })

    it("Should encrypt, LE and decrypt when first is larger", async function () {
      const { contract } = deployment

      await (await contract.leTest(5000000000n, 3000000000n)).wait()

      const decryptedInt = await contract.leResult()

      expect(decryptedInt).to.equal(false)
    })
  })

  describe("Offboard signed 128-bit integers", function () {
    it("Should offboard positive signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.offBoardTest(1000000000n, 2000000000n, 3000000000n)).wait()

      await (await contract.onBoardTest()).wait()

      const decryptedInt1 = await contract.onBoardResult1()
      const decryptedInt2 = await contract.onBoardResult2()

      expect(decryptedInt1).to.equal(1000000000n)
      expect(decryptedInt2).to.equal(3000000000n)
    })

    it("Should decrypt the positive signed 128-bit integers", async function () {
      const { contract, owner } = deployment

      const encryptedInt = await contract.offBoardToUserResult()

      const decryptedInt = await owner.decryptInt128(encryptedInt)

      expect(decryptedInt).to.equal(2000000000n)
    })

    it("Should offboard negative signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.offBoardTest(-1000000000n, -2000000000n, -3000000000n)).wait()

      await (await contract.onBoardTest()).wait()

      const decryptedInt1 = await contract.onBoardResult1()
      const decryptedInt2 = await contract.onBoardResult2()

      expect(decryptedInt1).to.equal(-1000000000n)
      expect(decryptedInt2).to.equal(-3000000000n)
    })

    it("Should decrypt the negative signed 128-bit integers", async function () {
      const { contract, owner } = deployment

      const encryptedInt = await contract.offBoardToUserResult()

      const decryptedInt = await owner.decryptInt128(encryptedInt)

      expect(decryptedInt).to.equal(-2000000000n)
    })
  })
}) 