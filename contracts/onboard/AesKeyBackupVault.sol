// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

/// @title AesKeyBackupVault
/// @notice Stores per-wallet EIP-712-wrapped AES-GCM backup blobs for cross-device restore.
/// @dev Ciphertext is public on-chain; decryption requires the wallet holder's signature off-chain.
contract AesKeyBackupVault {
    uint8 internal constant SUPPORTED_VERSION = 1;
    uint256 internal constant IV_LENGTH = 12;
    uint256 internal constant MIN_CIPHERTEXT_LENGTH = 32;
    uint256 internal constant MAX_CIPHERTEXT_LENGTH = 128;

    struct Backup {
        uint8 version;
        bytes iv;
        bytes ciphertext;
        uint64 updatedAt;
    }

    mapping(address => Backup) private _backups;

    event BackupSet(address indexed user, uint8 version, uint64 updatedAt);

    /// @notice Write or overwrite the caller's encrypted AES backup.
    /// @param version Backup format version (must be 1).
    /// @param iv AES-GCM nonce (exactly 12 bytes).
    /// @param ciphertext AES-GCM ciphertext including authentication tag.
    function setBackup(uint8 version, bytes calldata iv, bytes calldata ciphertext) external {
        require(version == SUPPORTED_VERSION, "unsupported version");
        require(iv.length == IV_LENGTH, "invalid iv length");
        require(
            ciphertext.length >= MIN_CIPHERTEXT_LENGTH && ciphertext.length <= MAX_CIPHERTEXT_LENGTH,
            "invalid ciphertext length"
        );

        _backups[msg.sender] = Backup({
            version: version,
            iv: iv,
            ciphertext: ciphertext,
            updatedAt: uint64(block.timestamp)
        });

        emit BackupSet(msg.sender, version, uint64(block.timestamp));
    }

    /// @notice Read a wallet's backup. Returns exists=false when no backup has been stored.
    function getBackup(address user)
        external
        view
        returns (bool exists, uint8 version, bytes memory iv, bytes memory ciphertext, uint64 updatedAt)
    {
        Backup storage backup = _backups[user];
        if (backup.iv.length == 0) {
            return (false, 0, "", "", 0);
        }

        return (true, backup.version, backup.iv, backup.ciphertext, backup.updatedAt);
    }

    /// @notice Cheap existence check for a wallet backup.
    function hasBackup(address user) external view returns (bool) {
        return _backups[user].iv.length > 0;
    }
}
