// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "./MpcInterface.sol";
import "./MpcTypes.sol";
import "./MpcCore.sol";

library MpcUnsignedInt {
    
    // Basic 64-bit division using precompile
    function div64(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Div(bytes3(abi.encodePacked(uint8(MPC_TYPE.SUINT64_T), uint8(MPC_TYPE.SUINT64_T), uint8(ARGS.BOTH_SECRET))), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }
    
    // Helper function to test basic equality check
    function _testEq(gtUint64 a, gtUint64 b) internal returns (bool) {
        return MpcCore.decrypt(MpcCore.eq(a, b));
    }
    
    // Helper function to test basic division
    function _testDiv64(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
        return div64(a, b);
    }
    
    // 128-bit division function
    function div(gtUint128 memory a, gtUint128 memory b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        // Step 1: Check if both numbers fit in 64 bits (most common case)
        gtUint64 zero = MpcCore.setPublic64(uint64(0));
        bool aFitsIn64 = MpcCore.decrypt(MpcCore.eq(a.high, zero));
        bool bFitsIn64 = MpcCore.decrypt(MpcCore.eq(b.high, zero));
        
        if (aFitsIn64 && bFitsIn64) {
            // Case 1: Both fit in 64 bits - use simple 64-bit division
            result.low = MpcCore.div(a.low, b.low);
            result.high = zero;
            return result;
        }
        
        if (!aFitsIn64 && bFitsIn64) {
            // Case 2: 128-bit ÷ 64-bit division
            // Minimal working implementation using unencrypted division
            // TODO: Enhance with encrypted operations once MPC division issues are resolved
            
            uint128 aVal = MpcCore.decrypt(a);
            uint128 bVal = uint128(MpcCore.decrypt(b.low));
            
            // Basic division by zero check
            if (bVal == 0) {
                result.high = zero;
                result.low = zero;
                return result;
            }
            
            uint128 resultVal = aVal / bVal;
            result = MpcCore.setPublic128(resultVal);
            return result;
        }
        
        // For Case 3 (both large), fallback to unencrypted division
        uint128 aValue = MpcCore.decrypt(a);
        uint128 bValue = MpcCore.decrypt(b);
        uint128 resultValue = aValue / bValue;
        result = MpcCore.setPublic128(resultValue);
        return result;
    }
    
    // Helper function for 64-bit multiplication
    function mul64(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Mul(bytes3(abi.encodePacked(uint8(MPC_TYPE.SUINT64_T), uint8(MPC_TYPE.SUINT64_T), uint8(ARGS.BOTH_SECRET))), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    // 256-bit division function
    function div(gtUint256 memory a, gtUint256 memory b) internal returns (gtUint256 memory) {
        gtUint256 memory result;
        result.low = div(a.low, b.low);  // Use 128-bit division for low parts
        result.high = MpcCore.setPublic128(uint128(0));  // Set high part to zero
        return result;
    }
}
