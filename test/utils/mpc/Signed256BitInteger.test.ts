import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"
import { generateRandomNumber } from "./helpers";

const gasLimit = 12000000

function randomSigned256() {
  let unsigned = generateRandomNumber(32);
  // If the most significant bit is set (i.e. sign bit), convert to signed using two's complement
  const signBit = 1n << 255n
  if (unsigned & signBit) {
      // Two's complement conversion for negative numbers
      unsigned = unsigned - (1n << 256n)
  }
  return unsigned
}

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
      const itValue = await owner.encryptInt256(
        testValue,
        contractAddress,
        contract.validateCiphertextTest.fragment.selector
      )
      await (await contract.validateCiphertextTest(itValue)).wait()
      const decryptedInt = await contract.validateResult()
      expect(decryptedInt).to.equal(testValue)
    })
    it("Should validate negative signed 256-bit integers", async function () {
      const { contract, contractAddress, owner } = deployment
      const testValue = -987654321098765432109876543210987654321n
      const itValue = await owner.encryptInt256(
        testValue,
        contractAddress,
        contract.validateCiphertextTest.fragment.selector
      )
      await (await contract.validateCiphertextTest(itValue)).wait()
      const decryptedInt = await contract.validateResult()
      expect(decryptedInt).to.equal(testValue)
    })
  })

  describe("Adding signed 256-bit integers", function () {
    it("Should encrypt, add and decrypt two positive signed 256-bit integers", async function () {
      const { contract } = deployment
      await (await contract.addTest(1000000000000000000000000000000000000000n, 2000000000000000000000000000000000000000n)).wait()
      const decryptedInt = await contract.addResult()
      expect(decryptedInt).to.equal(3000000000000000000000000000000000000000n)
    })
    it("Should encrypt, add and decrypt two negative signed 256-bit integers", async function () {
      const { contract } = deployment
      await (await contract.addTest(-1000000000000000000000000000000000000000n, -2000000000000000000000000000000000000000n)).wait()
      const decryptedInt = await contract.addResult()
      expect(decryptedInt).to.equal(-3000000000000000000000000000000000000000n)
    })
    it("Should encrypt, add and decrypt a positive and negative signed 256-bit integer", async function () {
      const { contract } = deployment
      await (await contract.addTest(5000000000000000000000000000000000000000n, -3000000000000000000000000000000000000000n)).wait()
      const decryptedInt = await contract.addResult()
      expect(decryptedInt).to.equal(2000000000000000000000000000000000000000n)
    })
    it("Should encrypt, add and decrypt a negative and positive signed 256-bit integer", async function () {
      const { contract } = deployment
      await (await contract.addTest(-8000000000000000000000000000000000000000n, 3000000000000000000000000000000000000000n)).wait()
      const decryptedInt = await contract.addResult()
      expect(decryptedInt).to.equal(-5000000000000000000000000000000000000000n)
    })
  })

  // Subtraction
  describe("Subtracting signed 256-bit integers", function () {
    it("Should encrypt, subtract and decrypt two positive signed 256-bit integers", async function () {
      const { contract } = deployment
      await (await contract.subTest(5000000000000000000000000000000000000000n, 2000000000000000000000000000000000000000n)).wait()
      const decryptedInt = await contract.subResult()
      expect(decryptedInt).to.equal(3000000000000000000000000000000000000000n)
    })
    it("Should encrypt, subtract and decrypt two negative signed 256-bit integers", async function () {
      const { contract } = deployment
      await (await contract.subTest(-5000000000000000000000000000000000000000n, -2000000000000000000000000000000000000000n)).wait()
      const decryptedInt = await contract.subResult()
      expect(decryptedInt).to.equal(-3000000000000000000000000000000000000000n)
    })
    it("Should encrypt, subtract and decrypt a positive and negative signed 256-bit integer", async function () {
      const { contract } = deployment
      await (await contract.subTest(5000000000000000000000000000000000000000n, -3000000000000000000000000000000000000000n)).wait()
      const decryptedInt = await contract.subResult()
      expect(decryptedInt).to.equal(8000000000000000000000000000000000000000n)
    })
    it("Should encrypt, subtract and decrypt a negative and positive signed 256-bit integer", async function () {
      const { contract } = deployment
      await (await contract.subTest(-8000000000000000000000000000000000000000n, 3000000000000000000000000000000000000000n)).wait()
      const decryptedInt = await contract.subResult()
      expect(decryptedInt).to.equal(-11000000000000000000000000000000000000000n)
    })
  })

  // Multiplication
  describe("Multiplying signed 256-bit integers", function () {
    it("Should encrypt, multiply and decrypt two positive signed 256-bit integers", async function () {
      const { contract } = deployment
      await (await contract.mulTest(1000000000000000n, 2000000000000n)).wait()
      const decryptedInt = await contract.mulResult()
      expect(decryptedInt).to.equal(2000000000000000000000000n)
    })
    it("Should encrypt, multiply and decrypt two negative signed 256-bit integers", async function () {
      const { contract } = deployment
      await (await contract.mulTest(-1000000000000000n, -3000000000000n)).wait()
      const decryptedInt = await contract.mulResult()
      expect(decryptedInt).to.equal(3000000000000000000000000n)
    })
    it("Should encrypt, multiply and decrypt a positive and negative signed 256-bit integer", async function () {
      const { contract } = deployment
      await (await contract.mulTest(2000000000000000n, -1500000000000n)).wait()
      const decryptedInt = await contract.mulResult()
      expect(decryptedInt).to.equal(-3000000000000000000000000n)
    })
    it("Should encrypt, multiply and decrypt a negative and positive signed 256-bit integer", async function () {
      const { contract } = deployment
      await (await contract.mulTest(-2000000000000000n, 1500000000000n)).wait()
      const decryptedInt = await contract.mulResult()
      expect(decryptedInt).to.equal(-3000000000000000000000000n)
    })
  })

  // Division
  describe("Dividing signed 256-bit integers", function () {
    it("Should encrypt, divide and decrypt two positive signed 256-bit integers", async function () {
      const { contract } = deployment
      await (await contract.divTest(6000000000000000000000000n, 2000000000000000000000000n)).wait()
      const decryptedInt = await contract.divResult()
      expect(decryptedInt).to.equal(3n)
    })
    it("Should encrypt, divide and decrypt two negative signed 256-bit integers", async function () {
      const { contract } = deployment
      await (await contract.divTest(-9000000000000000000000000n, -3000000000000000000000000n)).wait()
      const decryptedInt = await contract.divResult()
      expect(decryptedInt).to.equal(3n)
    })
    it("Should encrypt, divide and decrypt a positive and negative signed 256-bit integer", async function () {
      const { contract } = deployment
      await (await contract.divTest(8000000000000000000000000n, -2000000000000000000000000n)).wait()
      const decryptedInt = await contract.divResult()
      expect(decryptedInt).to.equal(-4n)
    })
    it("Should encrypt, divide and decrypt a negative and positive signed 256-bit integer", async function () {
      const { contract } = deployment
      await (await contract.divTest(-12000000000000000000000000n, 3000000000000000000000000n)).wait()
      const decryptedInt = await contract.divResult()
      expect(decryptedInt).to.equal(-4n)
    })
  })

  // Bitwise AND
  describe("AND signed 256-bit integers", function () {
    it("Should encrypt, AND and decrypt two positive signed 256-bit integers", async function () {
      const { contract } = deployment
      await (await contract.andTest(0xFFFFFFFn, 0x123456789n)).wait()
      const decryptedInt = await contract.andResult()
      expect(decryptedInt).to.equal(0x23456789n)
    })
    it("Should encrypt, AND and decrypt two negative signed 256-bit integers", async function () {
      const { contract } = deployment
      await (await contract.andTest(-1n, -1n)).wait()
      const decryptedInt = await contract.andResult()
      expect(decryptedInt).to.equal(-1n)
    })
    it("Should encrypt, AND and decrypt a positive and negative signed 256-bit integer", async function () {
      const { contract } = deployment
      await (await contract.andTest(0xFFFFFFFFn, -1n)).wait()
      const decryptedInt = await contract.andResult()
      expect(decryptedInt).to.equal(0xFFFFFFFFn)
    })
    it("Should encrypt, AND and decrypt a negative and positive signed 256-bit integer", async function () {
      const { contract } = deployment
      await (await contract.andTest(-2n, 1n)).wait()
      const decryptedInt = await contract.andResult()
      expect(decryptedInt).to.equal(0n)
    })
  })

  // Bitwise OR
  describe("OR signed 256-bit integers", function () {
    it("Should encrypt, OR and decrypt two positive signed 256-bit integers", async function () {
      const { contract } = deployment
      await (await contract.orTest(0xF0F0F0F0n, 0x0F0F0F0Fn)).wait()
      const decryptedInt = await contract.orResult()
      expect(decryptedInt).to.equal(0xFFFFFFFFn)
    })
    it("Should encrypt, OR and decrypt two negative signed 256-bit integers", async function () {
      const { contract } = deployment
      await (await contract.orTest(-1n, -1n)).wait()
      const decryptedInt = await contract.orResult()
      expect(decryptedInt).to.equal(-1n)
    })
    it("Should encrypt, OR and decrypt a positive and negative signed 256-bit integer", async function () {
      const { contract } = deployment
      await (await contract.orTest(1n, -1n)).wait()
      const decryptedInt = await contract.orResult()
      expect(decryptedInt).to.equal(-1n)
    })
    it("Should encrypt, OR and decrypt a negative and positive signed 256-bit integer", async function () {
      const { contract } = deployment
      await (await contract.orTest(-2n, 1n)).wait()
      const decryptedInt = await contract.orResult()
      expect(decryptedInt).to.equal(-1n)
    })
  })

  // Bitwise XOR
  describe("XOR signed 256-bit integers", function () {
    it("Should encrypt, XOR and decrypt two positive signed 256-bit integers", async function () {
      const { contract } = deployment
      await (await contract.xorTest(0xAAAAAAAAn, 0x55555555n)).wait()
      const decryptedInt = await contract.xorResult()
      expect(decryptedInt).to.equal(0xFFFFFFFFn)
    })
    it("Should encrypt, XOR and decrypt two negative signed 256-bit integers", async function () {
      const { contract } = deployment
      await (await contract.xorTest(-1n, -1n)).wait()
      const decryptedInt = await contract.xorResult()
      expect(decryptedInt).to.equal(0n)
    })
    it("Should encrypt, XOR and decrypt a positive and negative signed 256-bit integer", async function () {
      const { contract } = deployment
      await (await contract.xorTest(1n, -1n)).wait()
      const decryptedInt = await contract.xorResult()
      expect(decryptedInt).to.equal(-2n)
    })
    it("Should encrypt, XOR and decrypt a negative and positive signed 256-bit integer", async function () {
      const { contract } = deployment
      await (await contract.xorTest(-2n, 1n)).wait()
      const decryptedInt = await contract.xorResult()
      expect(decryptedInt).to.equal(-1n)
    })
  })

  // EQ
  describe("EQ signed 256-bit integers", function () {
    it("should return true for equal small positives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(123456789n, 123456789n)).wait()
      expect(await contract.eqResult()).to.equal(true)
    })
    it("should return false for different small positives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(123456789n, 987654321n)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for equal small negatives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(-123456789n, -123456789n)).wait()
      expect(await contract.eqResult()).to.equal(true)
    })
    it("should return false for different small negatives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(-123456789n, -987654321n)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small positive vs large positive", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = (2n ** 200n) + 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small negative vs large negative", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small positive vs large negative", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small negative vs large positive", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = (2n ** 200n) + 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for equal large positives", async function () {
      const { contract } = deployment
      const a = (2n ** 200n) + 123456789n
      await (await contract.eqTest(a, a)).wait()
      expect(await contract.eqResult()).to.equal(true)
    })
    it("should return false for different large positives", async function () {
      const { contract } = deployment
      const a = (2n ** 200n) + 123456789n
      const b = (2n ** 200n) + 987654321n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for equal large negatives", async function () {
      const { contract } = deployment
      const a = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(a, a)).wait()
      expect(await contract.eqResult()).to.equal(true)
    })
    it("should return false for different large negatives", async function () {
      const { contract } = deployment
      const a = -(2n ** 200n) - 123456789n
      const b = -(2n ** 200n) - 987654321n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for large positive vs large negative", async function () {
      const { contract } = deployment
      const a = (2n ** 200n) + 123456789n
      const b = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(b, a)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small positive vs large positive", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = (2n ** 200n) + 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small positive vs small negative", async function () {
      const { contract } = deployment
      await (await contract.eqTest(123456789n, -123456789n)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(-123456789n, 123456789n)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for large positive vs large negative", async function () {
      const { contract } = deployment
      const a = (2n ** 200n) + 123456789n
      const b = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(b, a)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small negative vs large negative", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should match equality for random 256-bit numbers", async function () {
      const { contract } = deployment
      for (let i = 0; i < 5; i++) {
        const a = randomSigned256()
        const b = randomSigned256()
        await (await contract.eqTest(a, b)).wait()
        expect(await contract.eqResult()).to.equal(a === b)
        await (await contract.eqTest(a, a)).wait()
        expect(await contract.eqResult()).to.equal(true)
      }
    })
  })

  // NE
  describe("NE signed 256-bit integers", function () {
    it("should return false for equal small positives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(123456789n, 123456789n)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for different small positives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(123456789n, 987654321n)).wait()
      expect(await contract.eqResult()).to.equal(true)
    })
    it("should return false for equal small negatives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(-123456789n, -123456789n)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for different small negatives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(-123456789n, -987654321n)).wait()
      expect(await contract.eqResult()).to.equal(true)
    })
    it("should return true for small positive vs large positive", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = (2n ** 200n) + 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for small negative vs large negative", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for small positive vs large negative", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for small negative vs large positive", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = (2n ** 200n) + 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for equal large positives", async function () {
      const { contract } = deployment
      const a = (2n ** 200n) + 123456789n
      await (await contract.eqTest(a, a)).wait()
      expect(await contract.eqResult()).to.equal(true)
    })
    it("should return true for different large positives", async function () {
      const { contract } = deployment
      const a = (2n ** 200n) + 123456789n
      const b = (2n ** 200n) + 987654321n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for equal large negatives", async function () {
      const { contract } = deployment
      const a = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(a, a)).wait()
      expect(await contract.eqResult()).to.equal(true)
    })
    it("should return true for different large negatives", async function () {
      const { contract } = deployment
      const a = -(2n ** 200n) - 123456789n
      const b = -(2n ** 200n) - 987654321n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for large positive vs large negative", async function () {
      const { contract } = deployment
      const a = (2n ** 200n) + 123456789n
      const b = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(b, a)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for small positive vs large positive", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = (2n ** 200n) + 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for small positive vs small negative", async function () {
      const { contract } = deployment
      await (await contract.eqTest(123456789n, -123456789n)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(-123456789n, 123456789n)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for large positive vs large negative", async function () {
      const { contract } = deployment
      const a = (2n ** 200n) + 123456789n
      const b = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(b, a)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for small negative vs large negative", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should match inequality for random 256-bit numbers", async function () {
      const { contract } = deployment
      for (let i = 0; i < 5; i++) {
        const a = randomSigned256()
        const b = randomSigned256()
        await (await contract.eqTest(a, b)).wait()
        expect(await contract.eqResult()).to.equal(a !== b)
      }
    })
  })

  // GT
  describe("GT signed 256-bit integers", function () {
    it("should return false for equal small positives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(123456789n, 123456789n)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for different small positives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(123456789n, 987654321n)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for equal small negatives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(-123456789n, -123456789n)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for different small negatives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(-123456789n, -987654321n)).wait()
      expect(await contract.eqResult()).to.equal(true)
    })
    it("should return false for small positive vs large positive", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = (2n ** 200n) + 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small negative vs large negative", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small positive vs large negative", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for small negative vs large positive", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = (2n ** 200n) + 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for equal large positives", async function () {
      const { contract } = deployment
      const a = (2n ** 200n) + 123456789n
      await (await contract.eqTest(a, a)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for different large positives", async function () {
      const { contract } = deployment
      const a = (2n ** 200n) + 123456789n
      const b = (2n ** 200n) + 987654321n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for equal large negatives", async function () {
      const { contract } = deployment
      const a = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(a, a)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for different large negatives", async function () {
      const { contract } = deployment
      const a = -(2n ** 200n) - 123456789n
      const b = -(2n ** 200n) - 987654321n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(true)
    })
    it("should return true for large positive vs large negative", async function () {
      const { contract } = deployment
      const a = (2n ** 200n) + 123456789n
      const b = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(true)
      await (await contract.eqTest(b, a)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small positive vs large positive", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = (2n ** 200n) + 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small positive vs small negative", async function () {
      const { contract } = deployment
      await (await contract.eqTest(123456789n, -123456789n)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(-123456789n, 123456789n)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for large positive vs large negative", async function () {
      const { contract } = deployment
      const a = (2n ** 200n) + 123456789n
      const b = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(true)
      await (await contract.eqTest(b, a)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small negative vs large negative", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should match greater than for random 256-bit numbers", async function () {
      const { contract } = deployment
      for (let i = 0; i < 5; i++) {
        const a = randomSigned256()
        const b = randomSigned256()
        await (await contract.eqTest(a, b)).wait()
        expect(await contract.eqResult()).to.equal(false)
        await (await contract.gtTest(a, b)).wait()
        expect(await contract.gtResult()).to.equal(a > b)
        await (await contract.gtTest(b, a)).wait()
        expect(await contract.gtResult()).to.equal(b > a)
      }
    })
  })

  // LT
  describe("LT signed 256-bit integers", function () {
    it("should return false for equal small positives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(123456789n, 123456789n)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for different small positives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(123456789n, 987654321n)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for equal small negatives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(-123456789n, -123456789n)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for different small negatives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(-123456789n, -987654321n)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for small positive vs large positive", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = (2n ** 200n) + 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small negative vs large negative", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small positive vs large negative", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small negative vs large positive", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = (2n ** 200n) + 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for equal large positives", async function () {
      const { contract } = deployment
      const a = (2n ** 200n) + 123456789n
      await (await contract.eqTest(a, a)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for different large positives", async function () {
      const { contract } = deployment
      const a = (2n ** 200n) + 123456789n
      const b = (2n ** 200n) + 987654321n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for equal large negatives", async function () {
      const { contract } = deployment
      const a = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(a, a)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for different large negatives", async function () {
      const { contract } = deployment
      const a = -(2n ** 200n) - 123456789n
      const b = -(2n ** 200n) - 987654321n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(true)
    })
    it("should return true for large positive vs large negative", async function () {
      const { contract } = deployment
      const a = (2n ** 200n) + 123456789n
      const b = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(true)
      await (await contract.eqTest(b, a)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small positive vs large positive", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = (2n ** 200n) + 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small positive vs small negative", async function () {
      const { contract } = deployment
      await (await contract.eqTest(123456789n, -123456789n)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(-123456789n, 123456789n)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for large positive vs large negative", async function () {
      const { contract } = deployment
      const a = (2n ** 200n) + 123456789n
      const b = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(true)
      await (await contract.eqTest(b, a)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small negative vs large negative", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should match less than for random 256-bit numbers", async function () {
      const { contract } = deployment
      for (let i = 0; i < 5; i++) {
        const a = randomSigned256()
        const b = randomSigned256()
        await (await contract.eqTest(a, b)).wait()
        expect(await contract.eqResult()).to.equal(false)
        await (await contract.ltTest(a, b)).wait()
        expect(await contract.ltResult()).to.equal(a < b)
        await (await contract.ltTest(b, a)).wait()
        expect(await contract.ltResult()).to.equal(b < a)
      }
    })
  })

  // GE
  describe("GE signed 256-bit integers", function () {
    it("should return true for equal small positives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(123456789n, 123456789n)).wait()
      expect(await contract.eqResult()).to.equal(true)
    })
    it("should return false for different small positives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(123456789n, 987654321n)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for equal small negatives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(-123456789n, -123456789n)).wait()
      expect(await contract.eqResult()).to.equal(true)
    })
    it("should return false for different small negatives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(-123456789n, -987654321n)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for small positive vs large positive", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = (2n ** 200n) + 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small negative vs large negative", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small positive vs large negative", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for small negative vs large positive", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = (2n ** 200n) + 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for equal large positives", async function () {
      const { contract } = deployment
      const a = (2n ** 200n) + 123456789n
      await (await contract.eqTest(a, a)).wait()
      expect(await contract.eqResult()).to.equal(true)
    })
    it("should return false for different large positives", async function () {
      const { contract } = deployment
      const a = (2n ** 200n) + 123456789n
      const b = (2n ** 200n) + 987654321n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for equal large negatives", async function () {
      const { contract } = deployment
      const a = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(a, a)).wait()
      expect(await contract.eqResult()).to.equal(true)
    })
    it("should return false for different large negatives", async function () {
      const { contract } = deployment
      const a = -(2n ** 200n) - 123456789n
      const b = -(2n ** 200n) - 987654321n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for large positive vs large negative", async function () {
      const { contract } = deployment
      const a = (2n ** 200n) + 123456789n
      const b = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(true)
      await (await contract.eqTest(b, a)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small positive vs large positive", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = (2n ** 200n) + 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small positive vs small negative", async function () {
      const { contract } = deployment
      await (await contract.eqTest(123456789n, -123456789n)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(-123456789n, 123456789n)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for large positive vs large negative", async function () {
      const { contract } = deployment
      const a = (2n ** 200n) + 123456789n
      const b = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(true)
      await (await contract.eqTest(b, a)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small negative vs large negative", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should match greater than or equal for random 256-bit numbers", async function () {
      const { contract } = deployment
      for (let i = 0; i < 5; i++) {
        const a = randomSigned256()
        const b = randomSigned256()
        await (await contract.eqTest(a, b)).wait()
        expect(await contract.eqResult()).to.equal(a === b)
        await (await contract.geTest(a, b)).wait()
        expect(await contract.geResult()).to.equal(a >= b)
        await (await contract.geTest(b, a)).wait()
        expect(await contract.geResult()).to.equal(b >= a)
      }
    })
  })

  // LE
  describe("LE signed 256-bit integers", function () {
    it("should return true for equal small positives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(123456789n, 123456789n)).wait()
      expect(await contract.eqResult()).to.equal(true)
    })
    it("should return false for different small positives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(123456789n, 987654321n)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for equal small negatives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(-123456789n, -123456789n)).wait()
      expect(await contract.eqResult()).to.equal(true)
    })
    it("should return false for different small negatives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(-123456789n, -987654321n)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for small positive vs large positive", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = (2n ** 200n) + 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small negative vs large negative", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small positive vs large negative", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for small negative vs large positive", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = (2n ** 200n) + 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for equal large positives", async function () {
      const { contract } = deployment
      const a = (2n ** 200n) + 123456789n
      await (await contract.eqTest(a, a)).wait()
      expect(await contract.eqResult()).to.equal(true)
    })
    it("should return false for different large positives", async function () {
      const { contract } = deployment
      const a = (2n ** 200n) + 123456789n
      const b = (2n ** 200n) + 987654321n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for equal large negatives", async function () {
      const { contract } = deployment
      const a = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(a, a)).wait()
      expect(await contract.eqResult()).to.equal(true)
    })
    it("should return false for different large negatives", async function () {
      const { contract } = deployment
      const a = -(2n ** 200n) - 123456789n
      const b = -(2n ** 200n) - 987654321n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for large positive vs large negative", async function () {
      const { contract } = deployment
      const a = (2n ** 200n) + 123456789n
      const b = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(true)
      await (await contract.eqTest(b, a)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small positive vs large positive", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = (2n ** 200n) + 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small positive vs small negative", async function () {
      const { contract } = deployment
      await (await contract.eqTest(123456789n, -123456789n)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(-123456789n, 123456789n)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for large positive vs large negative", async function () {
      const { contract } = deployment
      const a = (2n ** 200n) + 123456789n
      const b = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(true)
      await (await contract.eqTest(b, a)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small negative vs large negative", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = -(2n ** 200n) - 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should match less than or equal for random 256-bit numbers", async function () {
      const { contract } = deployment
      for (let i = 0; i < 5; i++) {
        const a = randomSigned256()
        const b = randomSigned256()
        await (await contract.eqTest(a, b)).wait()
        expect(await contract.eqResult()).to.equal(a === b)
        await (await contract.leTest(a, b)).wait()
        expect(await contract.leResult()).to.equal(a <= b)
        await (await contract.leTest(b, a)).wait()
        expect(await contract.leResult()).to.equal(b <= a)
      }
    })
  })

  // Offboard/Onboard
  describe("Offboard/Onboard signed 256-bit integers", function () {
    it("should return true for positive number offboard", async function () {
      const { contract } = deployment
      const testValue = 1234567890123456789012345678901234567890n
      const itValue = await contract.encryptInt256(
        testValue,
        contract.contractAddress,
        contract.offBoardTest.fragment.selector
      )
      await (await contract.offBoardTest(itValue)).wait()
      expect(await contract.offBoardResult()).to.equal(true)
    })
    it("should return false for positive number onboard", async function () {
      const { contract } = deployment
      const testValue = 1234567890123456789012345678901234567890n
      const itValue = await contract.encryptInt256(
        testValue,
        contract.contractAddress,
        contract.onBoardTest.fragment.selector
      )
      await (await contract.onBoardTest(itValue)).wait()
      expect(await contract.onBoardResult()).to.equal(false)
    })
    it("should return true for negative number offboard", async function () {
      const { contract } = deployment
      const testValue = -987654321098765432109876543210987654321n
      const itValue = await contract.encryptInt256(
        testValue,
        contract.contractAddress,
        contract.offBoardTest.fragment.selector
      )
      await (await contract.offBoardTest(itValue)).wait()
      expect(await contract.offBoardResult()).to.equal(true)
    })
    it("should return false for negative number onboard", async function () {
      const { contract } = deployment
      const testValue = -987654321098765432109876543210987654321n
      const itValue = await contract.encryptInt256(
        testValue,
        contract.contractAddress,
        contract.onBoardTest.fragment.selector
      )
      await (await contract.onBoardTest(itValue)).wait()
      expect(await contract.onBoardResult()).to.equal(false)
    })
    it("should return true for zero offboard", async function () {
      const { contract } = deployment
      const testValue = 0n
      const itValue = await contract.encryptInt256(
        testValue,
        contract.contractAddress,
        contract.offBoardTest.fragment.selector
      )
      await (await contract.offBoardTest(itValue)).wait()
      expect(await contract.offBoardResult()).to.equal(true)
    })
    it("should return false for zero onboard", async function () {
      const { contract } = deployment
      const testValue = 0n
      const itValue = await contract.encryptInt256(
        testValue,
        contract.contractAddress,
        contract.onBoardTest.fragment.selector
      )
      await (await contract.onBoardTest(itValue)).wait()
      expect(await contract.onBoardResult()).to.equal(false)
    })
    it("should return true for large positive number offboard", async function () {
      const { contract } = deployment
      const testValue = (2n ** 200n) + 123456789n
      const itValue = await contract.encryptInt256(
        testValue,
        contract.contractAddress,
        contract.offBoardTest.fragment.selector
      )
      await (await contract.offBoardTest(itValue)).wait()
      expect(await contract.offBoardResult()).to.equal(true)
    })
    it("should return false for large positive number onboard", async function () {
      const { contract } = deployment
      const testValue = (2n ** 200n) + 123456789n
      const itValue = await contract.encryptInt256(
        testValue,
        contract.contractAddress,
        contract.onBoardTest.fragment.selector
      )
      await (await contract.onBoardTest(itValue)).wait()
      expect(await contract.onBoardResult()).to.equal(false)
    })
    it("should return true for large negative number offboard", async function () {
      const { contract } = deployment
      const testValue = -(2n ** 200n) - 123456789n
      const itValue = await contract.encryptInt256(
        testValue,
        contract.contractAddress,
        contract.offBoardTest.fragment.selector
      )
      await (await contract.offBoardTest(itValue)).wait()
      expect(await contract.offBoardResult()).to.equal(true)
    })
    it("should return false for large negative number onboard", async function () {
      const { contract } = deployment
      const testValue = -(2n ** 200n) - 123456789n
      const itValue = await contract.encryptInt256(
        testValue,
        contract.contractAddress,
        contract.onBoardTest.fragment.selector
      )
      await (await contract.onBoardTest(itValue)).wait()
      expect(await contract.onBoardResult()).to.equal(false)
    })
    it("should return true for random positive number offboard", async function () {
      const { contract } = deployment
      const testValue = randomSigned256()
      const itValue = await contract.encryptInt256(
        testValue,
        contract.contractAddress,
        contract.offBoardTest.fragment.selector
      )
      await (await contract.offBoardTest(itValue)).wait()
      expect(await contract.offBoardResult()).to.equal(true)
    })
    it("should return false for random positive number onboard", async function () {
      const { contract } = deployment
      const testValue = randomSigned256()
      const itValue = await contract.encryptInt256(
        testValue,
        contract.contractAddress,
        contract.onBoardTest.fragment.selector
      )
      await (await contract.onBoardTest(itValue)).wait()
      expect(await contract.onBoardResult()).to.equal(false)
    })
    it("should return true for random negative number offboard", async function () {
      const { contract } = deployment
      const testValue = randomSigned256()
      const itValue = await contract.encryptInt256(
        testValue,
        contract.contractAddress,
        contract.offBoardTest.fragment.selector
      )
      await (await contract.offBoardTest(itValue)).wait()
      expect(await contract.offBoardResult()).to.equal(true)
    })
    it("should return false for random negative number onboard", async function () {
      const { contract } = deployment
      const testValue = randomSigned256()
      const itValue = await contract.encryptInt256(
        testValue,
        contract.contractAddress,
        contract.onBoardTest.fragment.selector
      )
      await (await contract.onBoardTest(itValue)).wait()
      expect(await contract.onBoardResult()).to.equal(false)
    })
  })

  // Fuzz/Randomized
  describe("Fuzzing signed 256-bit integers", function () {
    it("should return true for random positive number offboard", async function () {
      const { contract } = deployment
      const testValue = randomSigned256()
      const itValue = await contract.encryptInt256(
        testValue,
        contract.contractAddress,
        contract.offBoardTest.fragment.selector
      )
      await (await contract.offBoardTest(itValue)).wait()
      expect(await contract.offBoardResult()).to.equal(true)
    })
    it("should return false for random positive number onboard", async function () {
      const { contract } = deployment
      const testValue = randomSigned256()
      const itValue = await contract.encryptInt256(
        testValue,
        contract.contractAddress,
        contract.onBoardTest.fragment.selector
      )
      await (await contract.onBoardTest(itValue)).wait()
      expect(await contract.onBoardResult()).to.equal(false)
    })
    it("should return true for random negative number offboard", async function () {
      const { contract } = deployment
      const testValue = randomSigned256()
      const itValue = await contract.encryptInt256(
        testValue,
        contract.contractAddress,
        contract.offBoardTest.fragment.selector
      )
      await (await contract.offBoardTest(itValue)).wait()
      expect(await contract.offBoardResult()).to.equal(true)
    })
    it("should return false for random negative number onboard", async function () {
      const { contract } = deployment
      const testValue = randomSigned256()
      const itValue = await contract.encryptInt256(
        testValue,
        contract.contractAddress,
        contract.onBoardTest.fragment.selector
      )
      await (await contract.onBoardTest(itValue)).wait()
      expect(await contract.onBoardResult()).to.equal(false)
    })
  })
})
