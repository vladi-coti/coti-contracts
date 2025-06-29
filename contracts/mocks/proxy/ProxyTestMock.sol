// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../utils/mpc/MpcCore.sol";

contract ProxyTestMock {
    // Event to emit the validated gtUint256 values
    event PrivateParamsTest(gtUint256 gtParam);

    function validateSingleParam(itUint256 memory encryptedParam) external {
        // Validate encrypted inputs without decrypting
        gtUint256 memory gtParam = MpcCore.validateCiphertext(encryptedParam);

        emit PrivateParamsTest(gtParam);
    }
}
