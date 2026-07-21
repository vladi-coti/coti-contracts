import { expect } from "chai";
import hre from "hardhat";
import { ethers } from "hardhat";

const VERSION = 2;
const IV = ethers.hexlify(ethers.randomBytes(12));
const CIPHERTEXT = ethers.hexlify(ethers.randomBytes(48));

describe("AesKeyBackupVault", function () {
  async function deployVault() {
    const [owner, other] = await ethers.getSigners();
    const factory = await hre.ethers.getContractFactory("AesKeyBackupVault");
    const vault = await factory.deploy();
    await vault.waitForDeployment();
    return { vault, owner, other };
  }

  it("setBackup + getBackup roundtrip", async function () {
    const { vault, owner } = await deployVault();

    const tx = await vault.connect(owner).setBackup(VERSION, IV, CIPHERTEXT);
    await expect(tx).to.emit(vault, "BackupSet");
    const receipt = await tx.wait();
    const event = receipt?.logs
      .map((log) => {
        try {
          return vault.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((parsed) => parsed?.name === "BackupSet");
    expect(event?.args?.[0]).to.equal(owner.address);
    expect(event?.args?.[1]).to.equal(VERSION);
    expect(event?.args?.[2]).to.be.gt(0);

    const backup = await vault.getBackup(owner.address);
    expect(backup.exists).to.equal(true);
    expect(backup.version).to.equal(VERSION);
    expect(backup.iv).to.equal(IV);
    expect(backup.ciphertext).to.equal(CIPHERTEXT);
    expect(backup.updatedAt).to.be.gt(0);
    expect(await vault.hasBackup(owner.address)).to.equal(true);
  });

  it("overwrites an existing backup", async function () {
    const { vault, owner } = await deployVault();
    const iv2 = ethers.hexlify(ethers.randomBytes(12));
    const ciphertext2 = ethers.hexlify(ethers.randomBytes(40));

    await vault.connect(owner).setBackup(VERSION, IV, CIPHERTEXT);
    const firstUpdatedAt = (await vault.getBackup(owner.address)).updatedAt;

    await hre.network.provider.send("evm_increaseTime", [5]);
    await hre.network.provider.send("evm_mine", []);

    await vault.connect(owner).setBackup(VERSION, iv2, ciphertext2);
    const backup = await vault.getBackup(owner.address);

    expect(backup.iv).to.equal(iv2);
    expect(backup.ciphertext).to.equal(ciphertext2);
    expect(backup.updatedAt).to.be.gt(firstUpdatedAt);
  });

  it("rejects unsupported versions", async function () {
    const { vault, owner } = await deployVault();
    await expect(vault.connect(owner).setBackup(1, IV, CIPHERTEXT)).to.be.revertedWith(
      "unsupported version",
    );
  });

  it("rejects invalid iv length", async function () {
    const { vault, owner } = await deployVault();
    const shortIv = ethers.hexlify(ethers.randomBytes(8));
    await expect(vault.connect(owner).setBackup(VERSION, shortIv, CIPHERTEXT)).to.be.revertedWith(
      "invalid iv length",
    );
  });

  it("rejects invalid ciphertext length", async function () {
    const { vault, owner } = await deployVault();
    const shortCiphertext = ethers.hexlify(ethers.randomBytes(16));
    const longCiphertext = ethers.hexlify(ethers.randomBytes(129));

    await expect(
      vault.connect(owner).setBackup(VERSION, IV, shortCiphertext),
    ).to.be.revertedWith("invalid ciphertext length");
    await expect(
      vault.connect(owner).setBackup(VERSION, IV, longCiphertext),
    ).to.be.revertedWith("invalid ciphertext length");
  });

  it("returns exists=false before any backup is stored", async function () {
    const { vault, owner } = await deployVault();
    const backup = await vault.getBackup(owner.address);

    expect(backup.exists).to.equal(false);
    expect(backup.version).to.equal(0);
    expect(backup.iv).to.equal("0x");
    expect(backup.ciphertext).to.equal("0x");
    expect(backup.updatedAt).to.equal(0);
    expect(await vault.hasBackup(owner.address)).to.equal(false);
  });

  it("isolates backups per wallet", async function () {
    const { vault, owner, other } = await deployVault();
    const otherCiphertext = ethers.hexlify(ethers.randomBytes(48));

    await vault.connect(owner).setBackup(VERSION, IV, CIPHERTEXT);
    await vault.connect(other).setBackup(VERSION, IV, otherCiphertext);

    const ownerBackup = await vault.getBackup(owner.address);
    const otherBackup = await vault.getBackup(other.address);

    expect(ownerBackup.ciphertext).to.equal(CIPHERTEXT);
    expect(otherBackup.ciphertext).to.equal(otherCiphertext);
    expect(await vault.hasBackup(other.address)).to.equal(true);
  });
});
