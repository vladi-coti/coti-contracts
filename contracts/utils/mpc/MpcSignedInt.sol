// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "./MpcInterface.sol";
import "./MpcTypes.sol";
import { MpcCore } from "./MpcCore.sol";

library MpcSignedInt {
    // Helper function for boolean XOR
    function boolXor(gtBool a, gtBool b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Xor(
                    combineEnumsToBytes3(
                        MPC_TYPE.SBOOL_T,
                        MPC_TYPE.SBOOL_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtBool.unwrap(a),
                    gtBool.unwrap(b)
                )
            );
    }

    // =========== signed 8 bit operations ==============

    function validateCiphertext(itInt8 memory input) internal returns (gtInt8) {
        return
            gtInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).ValidateCiphertext(
                    bytes1(uint8(MPC_TYPE.SUINT8_T)),
                    ctInt8.unwrap(input.ciphertext),
                    input.signature
                )
            );
    }

    function onBoard(ctInt8 ct) internal returns (gtInt8) {
        return
            gtInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OnBoard(
                    bytes1(uint8(MPC_TYPE.SUINT8_T)),
                    ctInt8.unwrap(ct)
                )
            );
    }

    function offBoard(gtInt8 pt) internal returns (ctInt8) {
        return
            ctInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OffBoard(
                    bytes1(uint8(MPC_TYPE.SUINT8_T)),
                    gtInt8.unwrap(pt)
                )
            );
    }

    function offBoardToUser(gtInt8 pt, address addr) internal returns (ctInt8) {
        return
            ctInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OffBoardToUser(
                    bytes1(uint8(MPC_TYPE.SUINT8_T)),
                    gtInt8.unwrap(pt),
                    abi.encodePacked(addr)
                )
            );
    }

    function offBoardCombined(
        gtInt8 pt,
        address addr
    ) internal returns (utInt8 memory ut) {
        ut.ciphertext = offBoard(pt);
        ut.userCiphertext = offBoardToUser(pt, addr);
    }

    function setPublic8(int8 pt) internal returns (gtInt8) {
        // Simple approach: reinterpret the bits directly
        uint8 unsignedBits;
        assembly {
            unsignedBits := pt
        }
        return
            gtInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).SetPublic(
                    bytes1(uint8(MPC_TYPE.SUINT8_T)),
                    uint256(unsignedBits)
                )
            );
    }

    function add(gtInt8 a, gtInt8 b) internal returns (gtInt8) {
        return
            gtInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Add(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT8_T,
                        MPC_TYPE.SUINT8_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt8.unwrap(a),
                    gtInt8.unwrap(b)
                )
            );
    }

    function sub(gtInt8 a, gtInt8 b) internal returns (gtInt8) {
        return
            gtInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Sub(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT8_T,
                        MPC_TYPE.SUINT8_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt8.unwrap(a),
                    gtInt8.unwrap(b)
                )
            );
    }

    function mul(gtInt8 a, gtInt8 b) internal returns (gtInt8) {
        return
            gtInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mul(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT8_T,
                        MPC_TYPE.SUINT8_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt8.unwrap(a),
                    gtInt8.unwrap(b)
                )
            );
    }

    function div(gtInt8 a, gtInt8 b) internal returns (gtInt8) {
        // For now, implement simple direct division
        // TODO: Implement proper signed division logic
        return
            gtInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Div(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT8_T,
                        MPC_TYPE.SUINT8_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt8.unwrap(a),
                    gtInt8.unwrap(b)
                )
            );
    }

    function and(gtInt8 a, gtInt8 b) internal returns (gtInt8) {
        return
            gtInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).And(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT8_T,
                        MPC_TYPE.SUINT8_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt8.unwrap(a),
                    gtInt8.unwrap(b)
                )
            );
    }

    function or(gtInt8 a, gtInt8 b) internal returns (gtInt8) {
        return
            gtInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Or(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT8_T,
                        MPC_TYPE.SUINT8_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt8.unwrap(a),
                    gtInt8.unwrap(b)
                )
            );
    }

    function xor(gtInt8 a, gtInt8 b) internal returns (gtInt8) {
        return
            gtInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Xor(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT8_T,
                        MPC_TYPE.SUINT8_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt8.unwrap(a),
                    gtInt8.unwrap(b)
                )
            );
    }

    function eq(gtInt8 a, gtInt8 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Eq(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT8_T,
                        MPC_TYPE.SUINT8_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt8.unwrap(a),
                    gtInt8.unwrap(b)
                )
            );
    }

    function ne(gtInt8 a, gtInt8 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Ne(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT8_T,
                        MPC_TYPE.SUINT8_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt8.unwrap(a),
                    gtInt8.unwrap(b)
                )
            );
    }

    function gt(gtInt8 a, gtInt8 b) internal returns (gtBool) {
        gtUint8 aU = gtUint8.wrap(gtInt8.unwrap(a));
        gtUint8 bU = gtUint8.wrap(gtInt8.unwrap(b));
        gtUint8 signA = MpcCore.shr(aU, 7);
        gtUint8 signB = MpcCore.shr(bU, 7);
        gtBool signDiff = MpcCore.ne(MpcCore.eq(signA, MpcCore.setPublic8(uint8(1))), MpcCore.eq(signB, MpcCore.setPublic8(uint8(1))));
        gtBool aPos_bNeg = MpcCore.and(signDiff, MpcCore.eq(signA, MpcCore.setPublic8(uint8(0))));
        gtBool sameSign = MpcCore.eq(signA, signB);
        gtBool unsignedGt = MpcCore.gt(aU, bU);
        return MpcCore.or(aPos_bNeg, MpcCore.and(sameSign, unsignedGt));
    }

    function lt(gtInt8 a, gtInt8 b) internal returns (gtBool) {
        gtUint8 aU = gtUint8.wrap(gtInt8.unwrap(a));
        gtUint8 bU = gtUint8.wrap(gtInt8.unwrap(b));
        gtUint8 signA = MpcCore.shr(aU, 7);
        gtUint8 signB = MpcCore.shr(bU, 7);
        gtBool signDiff = MpcCore.ne(MpcCore.eq(signA, MpcCore.setPublic8(uint8(1))), MpcCore.eq(signB, MpcCore.setPublic8(uint8(1))));
        gtBool aNeg_bPos = MpcCore.and(signDiff, MpcCore.eq(signA, MpcCore.setPublic8(uint8(1))));
        gtBool sameSign = MpcCore.eq(signA, signB);
        gtBool unsignedLt = MpcCore.lt(aU, bU);
        return MpcCore.or(aNeg_bPos, MpcCore.and(sameSign, unsignedLt));
    }

    function ge(gtInt8 a, gtInt8 b) internal returns (gtBool) {
        gtBool isGt = gt(a, b);
        gtBool isEq = eq(a, b);
        return MpcCore.or(isGt, isEq);
    }

    function le(gtInt8 a, gtInt8 b) internal returns (gtBool) {
        gtBool isLt = lt(a, b);
        gtBool isEq = eq(a, b);
        return MpcCore.or(isLt, isEq);
    }

    function decrypt(gtInt8 ct) internal returns (int8) {
        return
            int8(
                uint8(
                    ExtendedOperations(address(MPC_PRECOMPILE)).Decrypt(
                        bytes1(uint8(MPC_TYPE.SUINT8_T)),
                        gtInt8.unwrap(ct)
                    )
                )
            );
    }

    function mux(gtBool bit, gtInt8 a, gtInt8 b) internal returns (gtInt8) {
        return
            gtInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mux(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT8_T,
                        MPC_TYPE.SUINT8_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtBool.unwrap(bit),
                    gtInt8.unwrap(a),
                    gtInt8.unwrap(b)
                )
            );
    }

    function shl(gtInt8 a, uint8 b) internal returns (gtInt8) {
        gtUint8 unsignedResult = MpcCore.shl(gtUint8.wrap(gtInt8.unwrap(a)), b);
        return gtInt8.wrap(gtUint8.unwrap(unsignedResult));
    }
    
    function shr(gtInt8 a, uint8 b) internal returns (gtInt8) {
        gtUint8 value = gtUint8.wrap(gtInt8.unwrap(a));
        gtUint8 shifted = MpcCore.shr(value, b);
        gtBool sign = MpcCore.eq(MpcCore.shr(value, 7), MpcCore.setPublic8(uint8(1)));
        if (b > 0) {
            if (MpcCore.decrypt(MpcCore.eq(sign, gtBool.wrap(1)))) {
                uint8 mask = uint8(type(uint8).max << (8 - b));
                shifted = MpcCore.or(shifted, MpcCore.setPublic8(mask));
            }
        }
        return gtInt8.wrap(gtUint8.unwrap(shifted));
    }

    // =========== signed 16 bit operations ==============

    function validateCiphertext(
        itInt16 memory input
    ) internal returns (gtInt16) {
        return
            gtInt16.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).ValidateCiphertext(
                    bytes1(uint8(MPC_TYPE.SUINT16_T)),
                    ctInt16.unwrap(input.ciphertext),
                    input.signature
                )
            );
    }

    function onBoard(ctInt16 ct) internal returns (gtInt16) {
        return
            gtInt16.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OnBoard(
                    bytes1(uint8(MPC_TYPE.SUINT16_T)),
                    ctInt16.unwrap(ct)
                )
            );
    }

    function offBoard(gtInt16 pt) internal returns (ctInt16) {
        return
            ctInt16.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OffBoard(
                    bytes1(uint8(MPC_TYPE.SUINT16_T)),
                    gtInt16.unwrap(pt)
                )
            );
    }

    function offBoardToUser(
        gtInt16 pt,
        address addr
    ) internal returns (ctInt16) {
        return
            ctInt16.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OffBoardToUser(
                    bytes1(uint8(MPC_TYPE.SUINT16_T)),
                    gtInt16.unwrap(pt),
                    abi.encodePacked(addr)
                )
            );
    }

    function offBoardCombined(
        gtInt16 pt,
        address addr
    ) internal returns (utInt16 memory ut) {
        ut.ciphertext = offBoard(pt);
        ut.userCiphertext = offBoardToUser(pt, addr);
    }

    function setPublic16(int16 pt) internal returns (gtInt16) {
        // Simple approach: reinterpret the bits directly
        uint16 unsignedBits;
        assembly {
            unsignedBits := pt
        }
        return
            gtInt16.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).SetPublic(
                    bytes1(uint8(MPC_TYPE.SUINT16_T)),
                    uint256(unsignedBits)
                )
            );
    }

    function add(gtInt16 a, gtInt16 b) internal returns (gtInt16) {
        return
            gtInt16.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Add(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT16_T,
                        MPC_TYPE.SUINT16_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt16.unwrap(a),
                    gtInt16.unwrap(b)
                )
            );
    }

    function sub(gtInt16 a, gtInt16 b) internal returns (gtInt16) {
        return
            gtInt16.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Sub(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT16_T,
                        MPC_TYPE.SUINT16_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt16.unwrap(a),
                    gtInt16.unwrap(b)
                )
            );
    }

    function mul(gtInt16 a, gtInt16 b) internal returns (gtInt16) {
        return
            gtInt16.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mul(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT16_T,
                        MPC_TYPE.SUINT16_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt16.unwrap(a),
                    gtInt16.unwrap(b)
                )
            );
    }

    function div(gtInt16 a, gtInt16 b) internal returns (gtInt16) {
        // Check if numbers are negative by testing the sign bit (bit 15 for int16)
        gtBool aNegative = eq(
            and(a, setPublic16(int16(-32768))), // -32768 = 0x8000 (sign bit set)
            setPublic16(int16(-32768))
        );

        gtBool bNegative = eq(
            and(b, setPublic16(int16(-32768))), // -32768 = 0x8000 (sign bit set)
            setPublic16(int16(-32768))
        );

        // Get absolute values: if negative, use two's complement negation
        gtInt16 aAbs = mux(
            aNegative,
            sub(setPublic16(int16(0)), a), // 0 - a
            a
        );

        gtInt16 bAbs = mux(
            bNegative,
            sub(setPublic16(int16(0)), b), // 0 - b
            b
        );

        // Perform unsigned division on absolute values
        gtInt16 unsignedResult = gtInt16.wrap(
            ExtendedOperations(address(MPC_PRECOMPILE)).Div(
                combineEnumsToBytes3(
                    MPC_TYPE.SUINT16_T,
                    MPC_TYPE.SUINT16_T,
                    ARGS.BOTH_SECRET
                ),
                gtInt16.unwrap(aAbs),
                gtInt16.unwrap(bAbs)
            )
        );

        // Result is negative if exactly one operand is negative
        gtBool resultNegative = boolXor(aNegative, bNegative);

        // Apply sign: if result should be negative, negate it
        return
            mux(
                resultNegative,
                sub(setPublic16(int16(0)), unsignedResult), // 0 - result
                unsignedResult
            );
    }

    function and(gtInt16 a, gtInt16 b) internal returns (gtInt16) {
        return
            gtInt16.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).And(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT16_T,
                        MPC_TYPE.SUINT16_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt16.unwrap(a),
                    gtInt16.unwrap(b)
                )
            );
    }

    function or(gtInt16 a, gtInt16 b) internal returns (gtInt16) {
        return
            gtInt16.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Or(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT16_T,
                        MPC_TYPE.SUINT16_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt16.unwrap(a),
                    gtInt16.unwrap(b)
                )
            );
    }

    function xor(gtInt16 a, gtInt16 b) internal returns (gtInt16) {
        return
            gtInt16.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Xor(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT16_T,
                        MPC_TYPE.SUINT16_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt16.unwrap(a),
                    gtInt16.unwrap(b)
                )
            );
    }

    function eq(gtInt16 a, gtInt16 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Eq(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT16_T,
                        MPC_TYPE.SUINT16_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt16.unwrap(a),
                    gtInt16.unwrap(b)
                )
            );
    }

    function ne(gtInt16 a, gtInt16 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Ne(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT16_T,
                        MPC_TYPE.SUINT16_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt16.unwrap(a),
                    gtInt16.unwrap(b)
                )
            );
    }

    function gt(gtInt16 a, gtInt16 b) internal returns (gtBool) {
        gtUint16 aU = gtUint16.wrap(gtInt16.unwrap(a));
        gtUint16 bU = gtUint16.wrap(gtInt16.unwrap(b));
        gtUint16 signA = MpcCore.shr(aU, 15);
        gtUint16 signB = MpcCore.shr(bU, 15);
        gtBool signDiff = MpcCore.ne(MpcCore.eq(signA, MpcCore.setPublic16(uint16(1))), MpcCore.eq(signB, MpcCore.setPublic16(uint16(1))));
        gtBool aPos_bNeg = MpcCore.and(signDiff, MpcCore.eq(signA, MpcCore.setPublic16(uint16(0))));
        gtBool sameSign = MpcCore.eq(signA, signB);
        gtBool unsignedGt = MpcCore.gt(aU, bU);
        return MpcCore.or(aPos_bNeg, MpcCore.and(sameSign, unsignedGt));
    }

    function lt(gtInt16 a, gtInt16 b) internal returns (gtBool) {
        gtUint16 aU = gtUint16.wrap(gtInt16.unwrap(a));
        gtUint16 bU = gtUint16.wrap(gtInt16.unwrap(b));
        gtUint16 signA = MpcCore.shr(aU, 15);
        gtUint16 signB = MpcCore.shr(bU, 15);
        gtBool signDiff = MpcCore.ne(MpcCore.eq(signA, MpcCore.setPublic16(uint16(1))), MpcCore.eq(signB, MpcCore.setPublic16(uint16(1))));
        gtBool aNeg_bPos = MpcCore.and(signDiff, MpcCore.eq(signA, MpcCore.setPublic16(uint16(1))));
        gtBool sameSign = MpcCore.eq(signA, signB);
        gtBool unsignedLt = MpcCore.lt(aU, bU);
        return MpcCore.or(aNeg_bPos, MpcCore.and(sameSign, unsignedLt));
    }

    function ge(gtInt16 a, gtInt16 b) internal returns (gtBool) {
        gtBool isGt = gt(a, b);
        gtBool isEq = eq(a, b);
        return MpcCore.or(isGt, isEq);
    }

    function le(gtInt16 a, gtInt16 b) internal returns (gtBool) {
        gtBool isLt = lt(a, b);
        gtBool isEq = eq(a, b);
        return MpcCore.or(isLt, isEq);
    }

    function decrypt(gtInt16 ct) internal returns (int16) {
        return
            int16(
                uint16(
                    ExtendedOperations(address(MPC_PRECOMPILE)).Decrypt(
                        bytes1(uint8(MPC_TYPE.SUINT16_T)),
                        gtInt16.unwrap(ct)
                    )
                )
            );
    }

    function mux(gtBool bit, gtInt16 a, gtInt16 b) internal returns (gtInt16) {
        return
            gtInt16.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mux(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT16_T,
                        MPC_TYPE.SUINT16_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtBool.unwrap(bit),
                    gtInt16.unwrap(a),
                    gtInt16.unwrap(b)
                )
            );
    }

    function shl(gtInt16 a, uint8 b) internal returns (gtInt16) {
        gtUint16 unsignedResult = MpcCore.shl(gtUint16.wrap(gtInt16.unwrap(a)), b);
        return gtInt16.wrap(gtUint16.unwrap(unsignedResult));
    }
    
    function shr(gtInt16 a, uint8 b) internal returns (gtInt16) {
        gtUint16 value = gtUint16.wrap(gtInt16.unwrap(a));
        gtUint16 shifted = MpcCore.shr(value, b);
        gtBool sign = MpcCore.eq(MpcCore.shr(value, 15), MpcCore.setPublic16(uint16(1)));
        if (b > 0) {
            if (MpcCore.decrypt(MpcCore.eq(sign, gtBool.wrap(1)))) {
                uint16 mask = uint16(type(uint16).max << (16 - b));
                shifted = MpcCore.or(shifted, MpcCore.setPublic16(mask));
            }
        }
        return gtInt16.wrap(gtUint16.unwrap(shifted));
    }

    // =========== signed 32 bit operations ==============

    function validateCiphertext(
        itInt32 memory input
    ) internal returns (gtInt32) {
        return
            gtInt32.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).ValidateCiphertext(
                    bytes1(uint8(MPC_TYPE.SUINT32_T)),
                    ctInt32.unwrap(input.ciphertext),
                    input.signature
                )
            );
    }

    function onBoard(ctInt32 ct) internal returns (gtInt32) {
        return
            gtInt32.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OnBoard(
                    bytes1(uint8(MPC_TYPE.SUINT32_T)),
                    ctInt32.unwrap(ct)
                )
            );
    }

    function offBoard(gtInt32 pt) internal returns (ctInt32) {
        return
            ctInt32.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OffBoard(
                    bytes1(uint8(MPC_TYPE.SUINT32_T)),
                    gtInt32.unwrap(pt)
                )
            );
    }

    function offBoardToUser(
        gtInt32 pt,
        address addr
    ) internal returns (ctInt32) {
        return
            ctInt32.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OffBoardToUser(
                    bytes1(uint8(MPC_TYPE.SUINT32_T)),
                    gtInt32.unwrap(pt),
                    abi.encodePacked(addr)
                )
            );
    }

    function offBoardCombined(
        gtInt32 pt,
        address addr
    ) internal returns (utInt32 memory ut) {
        ut.ciphertext = offBoard(pt);
        ut.userCiphertext = offBoardToUser(pt, addr);
    }

    function setPublic32(int32 pt) internal returns (gtInt32) {
        // Simple approach: reinterpret the bits directly
        uint32 unsignedBits;
        assembly {
            unsignedBits := pt
        }
        return
            gtInt32.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).SetPublic(
                    bytes1(uint8(MPC_TYPE.SUINT32_T)),
                    uint256(unsignedBits)
                )
            );
    }

    function add(gtInt32 a, gtInt32 b) internal returns (gtInt32) {
        return
            gtInt32.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Add(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT32_T,
                        MPC_TYPE.SUINT32_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt32.unwrap(a),
                    gtInt32.unwrap(b)
                )
            );
    }

    function sub(gtInt32 a, gtInt32 b) internal returns (gtInt32) {
        return
            gtInt32.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Sub(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT32_T,
                        MPC_TYPE.SUINT32_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt32.unwrap(a),
                    gtInt32.unwrap(b)
                )
            );
    }

    function mul(gtInt32 a, gtInt32 b) internal returns (gtInt32) {
        return
            gtInt32.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mul(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT32_T,
                        MPC_TYPE.SUINT32_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt32.unwrap(a),
                    gtInt32.unwrap(b)
                )
            );
    }

    function div(gtInt32 a, gtInt32 b) internal returns (gtInt32) {
        // Check if numbers are negative by testing the sign bit (bit 31 for int32)
        gtBool aNegative = eq(
            and(a, setPublic32(int32(-2147483648))), // -2147483648 = 0x80000000 (sign bit set)
            setPublic32(int32(-2147483648))
        );

        gtBool bNegative = eq(
            and(b, setPublic32(int32(-2147483648))), // -2147483648 = 0x80000000 (sign bit set)
            setPublic32(int32(-2147483648))
        );

        // Get absolute values: if negative, use two's complement negation
        gtInt32 aAbs = mux(
            aNegative,
            sub(setPublic32(int32(0)), a), // 0 - a
            a
        );

        gtInt32 bAbs = mux(
            bNegative,
            sub(setPublic32(int32(0)), b), // 0 - b
            b
        );

        // Perform unsigned division on absolute values
        gtInt32 unsignedResult = gtInt32.wrap(
            ExtendedOperations(address(MPC_PRECOMPILE)).Div(
                combineEnumsToBytes3(
                    MPC_TYPE.SUINT32_T,
                    MPC_TYPE.SUINT32_T,
                    ARGS.BOTH_SECRET
                ),
                gtInt32.unwrap(aAbs),
                gtInt32.unwrap(bAbs)
            )
        );

        // Result is negative if exactly one operand is negative
        gtBool resultNegative = boolXor(aNegative, bNegative);

        // Apply sign: if result should be negative, negate it
        return
            mux(
                resultNegative,
                sub(setPublic32(int32(0)), unsignedResult), // 0 - result
                unsignedResult
            );
    }

    function and(gtInt32 a, gtInt32 b) internal returns (gtInt32) {
        return
            gtInt32.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).And(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT32_T,
                        MPC_TYPE.SUINT32_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt32.unwrap(a),
                    gtInt32.unwrap(b)
                )
            );
    }

    function or(gtInt32 a, gtInt32 b) internal returns (gtInt32) {
        return
            gtInt32.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Or(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT32_T,
                        MPC_TYPE.SUINT32_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt32.unwrap(a),
                    gtInt32.unwrap(b)
                )
            );
    }

    function xor(gtInt32 a, gtInt32 b) internal returns (gtInt32) {
        return
            gtInt32.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Xor(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT32_T,
                        MPC_TYPE.SUINT32_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt32.unwrap(a),
                    gtInt32.unwrap(b)
                )
            );
    }

    function eq(gtInt32 a, gtInt32 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Eq(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT32_T,
                        MPC_TYPE.SUINT32_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt32.unwrap(a),
                    gtInt32.unwrap(b)
                )
            );
    }

    function ne(gtInt32 a, gtInt32 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Ne(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT32_T,
                        MPC_TYPE.SUINT32_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt32.unwrap(a),
                    gtInt32.unwrap(b)
                )
            );
    }

    function gt(gtInt32 a, gtInt32 b) internal returns (gtBool) {
        gtUint32 aU = gtUint32.wrap(gtInt32.unwrap(a));
        gtUint32 bU = gtUint32.wrap(gtInt32.unwrap(b));
        gtUint32 signA = MpcCore.shr(aU, 31);
        gtUint32 signB = MpcCore.shr(bU, 31);
        gtBool signDiff = MpcCore.ne(MpcCore.eq(signA, MpcCore.setPublic32(uint32(1))), MpcCore.eq(signB, MpcCore.setPublic32(uint32(1))));
        gtBool aPos_bNeg = MpcCore.and(signDiff, MpcCore.eq(signA, MpcCore.setPublic32(uint32(0))));
        gtBool sameSign = MpcCore.eq(signA, signB);
        gtBool unsignedGt = MpcCore.gt(aU, bU);
        return MpcCore.or(aPos_bNeg, MpcCore.and(sameSign, unsignedGt));
    }

    function lt(gtInt32 a, gtInt32 b) internal returns (gtBool) {
        gtUint32 aU = gtUint32.wrap(gtInt32.unwrap(a));
        gtUint32 bU = gtUint32.wrap(gtInt32.unwrap(b));
        gtUint32 signA = MpcCore.shr(aU, 31);
        gtUint32 signB = MpcCore.shr(bU, 31);
        gtBool signDiff = MpcCore.ne(MpcCore.eq(signA, MpcCore.setPublic32(uint32(1))), MpcCore.eq(signB, MpcCore.setPublic32(uint32(1))));
        gtBool aNeg_bPos = MpcCore.and(signDiff, MpcCore.eq(signA, MpcCore.setPublic32(uint32(1))));
        gtBool sameSign = MpcCore.eq(signA, signB);
        gtBool unsignedLt = MpcCore.lt(aU, bU);
        return MpcCore.or(aNeg_bPos, MpcCore.and(sameSign, unsignedLt));
    }

    function ge(gtInt32 a, gtInt32 b) internal returns (gtBool) {
        gtBool isGt = gt(a, b);
        gtBool isEq = eq(a, b);
        return MpcCore.or(isGt, isEq);
    }

    function le(gtInt32 a, gtInt32 b) internal returns (gtBool) {
        gtBool isLt = lt(a, b);
        gtBool isEq = eq(a, b);
        return MpcCore.or(isLt, isEq);
    }

    function decrypt(gtInt32 ct) internal returns (int32) {
        return
            int32(
                uint32(
                    ExtendedOperations(address(MPC_PRECOMPILE)).Decrypt(
                        bytes1(uint8(MPC_TYPE.SUINT32_T)),
                        gtInt32.unwrap(ct)
                    )
                )
            );
    }

    function mux(gtBool bit, gtInt32 a, gtInt32 b) internal returns (gtInt32) {
        return
            gtInt32.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mux(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT32_T,
                        MPC_TYPE.SUINT32_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtBool.unwrap(bit),
                    gtInt32.unwrap(a),
                    gtInt32.unwrap(b)
                )
            );
    }

    function shl(gtInt32 a, uint8 b) internal returns (gtInt32) {
        gtUint32 unsignedResult = MpcCore.shl(gtUint32.wrap(gtInt32.unwrap(a)), b);
        return gtInt32.wrap(gtUint32.unwrap(unsignedResult));
    }

    function shr(gtInt32 a, uint8 b) internal returns (gtInt32) {
        gtUint32 value = gtUint32.wrap(gtInt32.unwrap(a));
        gtUint32 shifted = MpcCore.shr(value, b);
        gtBool sign = MpcCore.eq(MpcCore.shr(value, 31), MpcCore.setPublic32(uint32(1)));
        if (b > 0) {
            if (MpcCore.decrypt(MpcCore.eq(sign, gtBool.wrap(1)))) {
                uint32 mask = uint32(type(uint32).max << (32 - b));
                shifted = MpcCore.or(shifted, MpcCore.setPublic32(mask));
            }
        }
        return gtInt32.wrap(gtUint32.unwrap(shifted));
    }

    // =========== signed 64 bit operations ==============

    function validateCiphertext(
        itInt64 memory input
    ) internal returns (gtInt64) {
        return
            gtInt64.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).ValidateCiphertext(
                    bytes1(uint8(MPC_TYPE.SUINT64_T)),
                    ctInt64.unwrap(input.ciphertext),
                    input.signature
                )
            );
    }

    function onBoard(ctInt64 ct) internal returns (gtInt64) {
        return
            gtInt64.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OnBoard(
                    bytes1(uint8(MPC_TYPE.SUINT64_T)),
                    ctInt64.unwrap(ct)
                )
            );
    }

    function offBoard(gtInt64 pt) internal returns (ctInt64) {
        return
            ctInt64.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OffBoard(
                    bytes1(uint8(MPC_TYPE.SUINT64_T)),
                    gtInt64.unwrap(pt)
                )
            );
    }

    function offBoardToUser(
        gtInt64 pt,
        address addr
    ) internal returns (ctInt64) {
        return
            ctInt64.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OffBoardToUser(
                    bytes1(uint8(MPC_TYPE.SUINT64_T)),
                    gtInt64.unwrap(pt),
                    abi.encodePacked(addr)
                )
            );
    }

    function offBoardCombined(
        gtInt64 pt,
        address addr
    ) internal returns (utInt64 memory ut) {
        ut.ciphertext = offBoard(pt);
        ut.userCiphertext = offBoardToUser(pt, addr);
    }

    function setPublic64(int64 pt) internal returns (gtInt64) {
        return
            gtInt64.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).SetPublic(
                    bytes1(uint8(MPC_TYPE.SUINT64_T)),
                    uint256(uint64(uint256(int256(pt))))
                )
            );
    }

    function add(gtInt64 a, gtInt64 b) internal returns (gtInt64) {
        return
            gtInt64.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Add(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT64_T,
                        MPC_TYPE.SUINT64_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt64.unwrap(a),
                    gtInt64.unwrap(b)
                )
            );
    }

    function sub(gtInt64 a, gtInt64 b) internal returns (gtInt64) {
        return
            gtInt64.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Sub(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT64_T,
                        MPC_TYPE.SUINT64_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt64.unwrap(a),
                    gtInt64.unwrap(b)
                )
            );
    }

    function mul(gtInt64 a, gtInt64 b) internal returns (gtInt64) {
        return
            gtInt64.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mul(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT64_T,
                        MPC_TYPE.SUINT64_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt64.unwrap(a),
                    gtInt64.unwrap(b)
                )
            );
    }

    function div(gtInt64 a, gtInt64 b) internal returns (gtInt64) {
        // Check if numbers are negative by testing the sign bit (bit 63 for int64)
        gtBool aNegative = eq(
            and(a, setPublic64(int64(-9223372036854775808))), // min int64 value (sign bit set)
            setPublic64(int64(-9223372036854775808))
        );

        gtBool bNegative = eq(
            and(b, setPublic64(int64(-9223372036854775808))), // min int64 value (sign bit set)
            setPublic64(int64(-9223372036854775808))
        );

        // Get absolute values: if negative, use two's complement negation
        gtInt64 aAbs = mux(
            aNegative,
            sub(setPublic64(int64(0)), a), // 0 - a
            a
        );

        gtInt64 bAbs = mux(
            bNegative,
            sub(setPublic64(int64(0)), b), // 0 - b
            b
        );

        // Perform unsigned division on absolute values
        gtInt64 unsignedResult = gtInt64.wrap(
            ExtendedOperations(address(MPC_PRECOMPILE)).Div(
                combineEnumsToBytes3(
                    MPC_TYPE.SUINT64_T,
                    MPC_TYPE.SUINT64_T,
                    ARGS.BOTH_SECRET
                ),
                gtInt64.unwrap(aAbs),
                gtInt64.unwrap(bAbs)
            )
        );

        // Result is negative if exactly one operand is negative
        gtBool resultNegative = boolXor(aNegative, bNegative);

        // Apply sign: if result should be negative, negate it
        return
            mux(
                resultNegative,
                sub(setPublic64(int64(0)), unsignedResult), // 0 - result
                unsignedResult
            );
    }

    function and(gtInt64 a, gtInt64 b) internal returns (gtInt64) {
        return
            gtInt64.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).And(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT64_T,
                        MPC_TYPE.SUINT64_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt64.unwrap(a),
                    gtInt64.unwrap(b)
                )
            );
    }

    function or(gtInt64 a, gtInt64 b) internal returns (gtInt64) {
        return
            gtInt64.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Or(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT64_T,
                        MPC_TYPE.SUINT64_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt64.unwrap(a),
                    gtInt64.unwrap(b)
                )
            );
    }

    function xor(gtInt64 a, gtInt64 b) internal returns (gtInt64) {
        return
            gtInt64.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Xor(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT64_T,
                        MPC_TYPE.SUINT64_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt64.unwrap(a),
                    gtInt64.unwrap(b)
                )
            );
    }

    function eq(gtInt64 a, gtInt64 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Eq(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT64_T,
                        MPC_TYPE.SUINT64_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt64.unwrap(a),
                    gtInt64.unwrap(b)
                )
            );
    }

    function ne(gtInt64 a, gtInt64 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Ne(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT64_T,
                        MPC_TYPE.SUINT64_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt64.unwrap(a),
                    gtInt64.unwrap(b)
                )
            );
    }

    function gt(gtInt64 a, gtInt64 b) internal returns (gtBool) {
        gtUint64 aU = gtUint64.wrap(gtInt64.unwrap(a));
        gtUint64 bU = gtUint64.wrap(gtInt64.unwrap(b));
        gtUint64 signA = MpcCore.shr(aU, 63);
        gtUint64 signB = MpcCore.shr(bU, 63);
        gtBool signDiff = MpcCore.ne(MpcCore.eq(signA, MpcCore.setPublic64(uint64(1))), MpcCore.eq(signB, MpcCore.setPublic64(uint64(1))));
        gtBool aPos_bNeg = MpcCore.and(signDiff, MpcCore.eq(signA, MpcCore.setPublic64(uint64(0))));
        gtBool sameSign = MpcCore.eq(signA, signB);
        gtBool unsignedGt = MpcCore.gt(aU, bU);
        return MpcCore.or(aPos_bNeg, MpcCore.and(sameSign, unsignedGt));
    }

    function lt(gtInt64 a, gtInt64 b) internal returns (gtBool) {
        gtUint64 aU = gtUint64.wrap(gtInt64.unwrap(a));
        gtUint64 bU = gtUint64.wrap(gtInt64.unwrap(b));
        gtUint64 signA = MpcCore.shr(aU, 63);
        gtUint64 signB = MpcCore.shr(bU, 63);
        gtBool signDiff = MpcCore.ne(MpcCore.eq(signA, MpcCore.setPublic64(uint64(1))), MpcCore.eq(signB, MpcCore.setPublic64(uint64(1))));
        gtBool aNeg_bPos = MpcCore.and(signDiff, MpcCore.eq(signA, MpcCore.setPublic64(uint64(1))));
        gtBool sameSign = MpcCore.eq(signA, signB);
        gtBool unsignedLt = MpcCore.lt(aU, bU);
        return MpcCore.or(aNeg_bPos, MpcCore.and(sameSign, unsignedLt));
    }

    function ge(gtInt64 a, gtInt64 b) internal returns (gtBool) {
        gtBool isGt = gt(a, b);
        gtBool isEq = eq(a, b);
        return MpcCore.or(isGt, isEq);
    }
    
    function le(gtInt64 a, gtInt64 b) internal returns (gtBool) {
        gtBool isLt = lt(a, b);
        gtBool isEq = eq(a, b);
        return MpcCore.or(isLt, isEq);
    }

    function decrypt(gtInt64 ct) internal returns (int64) {
        return
            int64(
                uint64(
                    ExtendedOperations(address(MPC_PRECOMPILE)).Decrypt(
                        bytes1(uint8(MPC_TYPE.SUINT64_T)),
                        gtInt64.unwrap(ct)
                    )
                )
            );
    }

    function mux(gtBool bit, gtInt64 a, gtInt64 b) internal returns (gtInt64) {
        return
            gtInt64.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mux(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT64_T,
                        MPC_TYPE.SUINT64_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtBool.unwrap(bit),
                    gtInt64.unwrap(a),
                    gtInt64.unwrap(b)
                )
            );
    }

    function shl(gtInt64 a, uint8 b) internal returns (gtInt64) {
        gtUint64 unsignedResult = MpcCore.shl(gtUint64.wrap(gtInt64.unwrap(a)), b);
        return gtInt64.wrap(gtUint64.unwrap(unsignedResult));
    }

    function shr(gtInt64 a, uint8 b) internal returns (gtInt64) {
        gtUint64 value = gtUint64.wrap(gtInt64.unwrap(a));
        gtUint64 shifted = MpcCore.shr(value, b);
        gtBool sign = MpcCore.eq(MpcCore.shr(value, 63), MpcCore.setPublic64(uint64(1)));
        if (b > 0) {
            if (MpcCore.decrypt(MpcCore.eq(sign, gtBool.wrap(1)))) {
                uint64 mask = uint64(type(uint64).max << (64 - b));
                shifted = MpcCore.or(shifted, MpcCore.setPublic64(mask));
            }
        }
        return gtInt64.wrap(gtUint64.unwrap(shifted));
    }

    // =========== signed 128 bit operations ==============

    function validateCiphertext(
        itInt128 memory input
    ) internal returns (gtInt128 memory) {
        gtInt128 memory result;

        itInt64 memory highInput;
        highInput.ciphertext = input.ciphertext.high;
        highInput.signature = input.signature[0];

        itInt64 memory lowInput;
        lowInput.ciphertext = input.ciphertext.low;
        lowInput.signature = input.signature[1];

        result.high = validateCiphertext(highInput);
        result.low = validateCiphertext(lowInput);

        return result;
    }

    function onBoard(ctInt128 memory ct) internal returns (gtInt128 memory) {
        gtInt128 memory result;

        result.high = onBoard(ct.high);
        result.low = onBoard(ct.low);

        return result;
    }

    function offBoard(gtInt128 memory pt) internal returns (ctInt128 memory) {
        ctInt128 memory result;

        result.high = offBoard(pt.high);
        result.low = offBoard(pt.low);

        return result;
    }

    function offBoardToUser(
        gtInt128 memory pt,
        address addr
    ) internal returns (ctInt128 memory) {
        ctInt128 memory result;

        result.high = offBoardToUser(pt.high, addr);
        result.low = offBoardToUser(pt.low, addr);

        return result;
    }

    function offBoardCombined(
        gtInt128 memory pt,
        address addr
    ) internal returns (utInt128 memory) {
        utInt128 memory result;

        result.ciphertext = offBoard(pt);
        result.userCiphertext = offBoardToUser(pt, addr);

        return result;
    }

    // Helper to reinterpret int64 as uint64 (preserve bits)
    function int64ToUint64(int64 x) internal pure returns (uint64) {
        return uint64(uint256(uint64(x)));
    }
    // Helper to reinterpret uint64 as int64 (preserve bits)
    function uint64ToInt64(uint64 x) internal pure returns (int64) {
        return int64(uint64(uint256(x)));
    }

    function setPublic128(int128 pt) internal returns (gtInt128 memory) {
        gtInt128 memory result;

        // Correctly split the 128-bit value into high and low 64-bit parts
        uint64 low = uint64(uint128(pt));
        int64 high = int64(pt >> 64);

        result.high = setPublic64(high);
        result.low = setPublic64(uint64ToInt64(low));

        return result;
    }

    function add(
        gtInt128 memory a,
        gtInt128 memory b
    ) internal returns (gtInt128 memory) {
        gtInt128 memory result;

        // Add low parts using gtInt64 addition
        result.low = add(a.low, b.low);

        // Simple carry detection: if result is less than one operand, there was overflow
        gtBool overflow_low = gtBool.wrap(
            ExtendedOperations(address(MPC_PRECOMPILE)).Lt(
                combineEnumsToBytes3(
                    MPC_TYPE.SUINT64_T,
                    MPC_TYPE.SUINT64_T,
                    ARGS.BOTH_SECRET
                ),
                gtInt64.unwrap(result.low),
                gtInt64.unwrap(a.low)
            )
        );

        // Add high parts
        result.high = add(a.high, b.high);

        // Add carry to high part if needed
        result.high = mux(
            overflow_low,
            result.high,
            add(result.high, setPublic64(int64(1)))
        );

        return result;
    }

    function sub(
        gtInt128 memory a,
        gtInt128 memory b
    ) internal returns (gtInt128 memory) {
        gtInt128 memory result;

        // Subtract low parts
        result.low = sub(a.low, b.low);

        // Simple borrow detection: if a.low < b.low, there was underflow
        gtBool borrow = gtBool.wrap(
            ExtendedOperations(address(MPC_PRECOMPILE)).Lt(
                combineEnumsToBytes3(
                    MPC_TYPE.SUINT64_T,
                    MPC_TYPE.SUINT64_T,
                    ARGS.BOTH_SECRET
                ),
                gtInt64.unwrap(a.low),
                gtInt64.unwrap(b.low)
            )
        );

        // Subtract high parts with borrow if needed
        result.high = sub(a.high, b.high);

        // Subtract borrow from high part if needed
        result.high = mux(
            borrow,
            result.high,
            sub(result.high, setPublic64(int64(1)))
        );

        return result;
    }

    function mul(
        gtInt128 memory a,
        gtInt128 memory b
    ) internal returns (gtInt128 memory) {
        // Determine if a and b are negative (sign bit of high part)
        gtBool aNegative = MpcCore.lt(a.high, MpcCore.setPublic64(int64(0)));
        gtBool bNegative = MpcCore.lt(b.high, MpcCore.setPublic64(int64(0)));

        // Get absolute values
        gtInt128 memory aAbs = MpcCore.mux(aNegative, negate(a), a);
        gtInt128 memory bAbs = MpcCore.mux(bNegative, negate(b), b);

        // Convert to unsigned for multiplication
        gtUint128 memory aAbsU = toUint128(aAbs);
        gtUint128 memory bAbsU = toUint128(bAbs);

        // Use unsigned 128-bit multiplication
        gtUint128 memory unsignedResultU = MpcCore.mul(aAbsU, bAbsU);

        // Convert back to signed
        gtInt128 memory unsignedResult = fromUint128(unsignedResultU);

        // Result is negative if exactly one operand is negative
        gtBool resultNegative = MpcCore.xor(aNegative, bNegative);

        // Apply sign
        return MpcCore.mux(resultNegative, unsignedResult, negate(unsignedResult));
    }

    function div(
        gtInt128 memory a,
        gtInt128 memory b
    ) internal returns (gtInt128 memory) {
        // For now, use selective decryption for all cases to ensure correctness
        int128 aValue = decrypt(a);
        int128 bValue = decrypt(b);
        
        if (bValue == 0) {
            return setPublic128(int128(0));
        }
        
        // Handle the overflow case: MIN / -1 = -MIN, but -MIN overflows
        // In 2's complement, this wraps around to MIN itself
        if (aValue == type(int128).min && bValue == -1) {
            return setPublic128(type(int128).min);
        }
        
        int128 resultValue = aValue / bValue;
        return setPublic128(resultValue);
    }

    function negate(gtInt128 memory a) internal returns (gtInt128 memory) {
        gtInt128 memory result;

        // Two's complement negation: ~a + 1
        result.low = xor(a.low, setPublic64(int64(-1)));
        result.high = xor(a.high, setPublic64(int64(-1)));

        // Add 1
        result = add(result, setPublic128(int128(1)));

        return result;
    }

    function and(
        gtInt128 memory a,
        gtInt128 memory b
    ) internal returns (gtInt128 memory) {
        gtInt128 memory result;

        result.low = and(a.low, b.low);
        result.high = and(a.high, b.high);

        return result;
    }

    function or(
        gtInt128 memory a,
        gtInt128 memory b
    ) internal returns (gtInt128 memory) {
        gtInt128 memory result;

        result.low = or(a.low, b.low);
        result.high = or(a.high, b.high);

        return result;
    }

    function xor(
        gtInt128 memory a,
        gtInt128 memory b
    ) internal returns (gtInt128 memory) {
        gtInt128 memory result;

        result.low = xor(a.low, b.low);
        result.high = xor(a.high, b.high);

        return result;
    }

    function eq(
        gtInt128 memory a,
        gtInt128 memory b
    ) internal returns (gtBool) {
        gtBool lowEqual = eq(a.low, b.low);
        gtBool highEqual = eq(a.high, b.high);
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).And(
                    combineEnumsToBytes3(
                        MPC_TYPE.SBOOL_T,
                        MPC_TYPE.SBOOL_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtBool.unwrap(lowEqual),
                    gtBool.unwrap(highEqual)
                )
            );
    }

    function ne(
        gtInt128 memory a,
        gtInt128 memory b
    ) internal returns (gtBool) {
        gtBool lowNotEqual = ne(a.low, b.low);
        gtBool highNotEqual = ne(a.high, b.high);
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Or(
                    combineEnumsToBytes3(
                        MPC_TYPE.SBOOL_T,
                        MPC_TYPE.SBOOL_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtBool.unwrap(lowNotEqual),
                    gtBool.unwrap(highNotEqual)
                )
            );
    }

    function ge(gtInt128 memory a, gtInt128 memory b) internal returns (gtBool) {
        gtBool highEqual = eq(a.high, b.high);

        return MpcCore.mux(highEqual, gt(a.high, b.high), ge(a.low, b.low));
    }

    function gt(gtInt128 memory a, gtInt128 memory b) internal returns (gtBool) {
        // Compare high parts as signed 64-bit
        gtBool highGt = gt(a.high, b.high);
        gtBool highEq = eq(a.high, b.high);
        // Compare low parts as unsigned 64-bit if high parts are equal
        gtBool lowGt = MpcCore.gt(gtUint64.wrap(gtInt64.unwrap(a.low)), gtUint64.wrap(gtInt64.unwrap(b.low)));
        return MpcCore.or(highGt, MpcCore.and(highEq, lowGt));
    }

    function lt(gtInt128 memory a, gtInt128 memory b) internal returns (gtBool) {
        // Compare high parts as signed 64-bit
        gtBool highLt = lt(a.high, b.high);
        gtBool highEq = eq(a.high, b.high);
        // Compare low parts as unsigned 64-bit if high parts are equal
        gtBool lowLt = MpcCore.lt(gtUint64.wrap(gtInt64.unwrap(a.low)), gtUint64.wrap(gtInt64.unwrap(b.low)));
        return MpcCore.or(highLt, MpcCore.and(highEq, lowLt));
    }

    function le(gtInt128 memory a, gtInt128 memory b) internal returns (gtBool) {
        gtBool highLt = lt(a.high, b.high); // signed 64-bit
        gtBool highEq = eq(a.high, b.high);
        // Compare low as unsigned if high parts are equal
        gtBool lowLe = MpcCore.le(gtUint64.wrap(gtInt64.unwrap(a.low)), gtUint64.wrap(gtInt64.unwrap(b.low)));
        return MpcCore.or(highLt, MpcCore.and(highEq, lowLe));
    }

    function decrypt(gtInt128 memory ct) internal returns (int128) {
        int64 highPart = decrypt(ct.high);
        int64 lowPartSigned = decrypt(ct.low);
        uint64 lowPart = int64ToUint64(lowPartSigned);

        // Combine high and low parts properly
        return (int128(highPart) << 64) | int128(int128(uint128(uint256(lowPart))));
    }

    function mux(
        gtBool bit,
        gtInt128 memory a,
        gtInt128 memory b
    ) internal returns (gtInt128 memory) {
        gtInt128 memory result;

        result.low = mux(bit, a.low, b.low);
        result.high = mux(bit, a.high, b.high);

        return result;
    }

    function shl(gtInt128 memory a, uint8 b) internal returns (gtInt128 memory) {
        gtInt128 memory result;
        result.low = shl(a.low, b);
        result.high = shl(a.high, b);
        return result;
    }
    
    function shr(gtInt128 memory a, uint8 b) internal returns (gtInt128 memory) {
        gtInt128 memory result;
        // If shifting by 128 or more, result is all sign bits
        gtBool sign = eq(shr(a.high, 63), setPublic64(int64(1)));
        if (b >= 128) {
            if (MpcCore.decrypt(sign)) {
                result.high = setPublic64(int64(type(uint64).max));
                result.low = setPublic64(int64(type(uint64).max));
            } else {
                result.high = setPublic64(int64(0));
                result.low = setPublic64(int64(0));
            }
        } else if (b >= 64) {
            uint8 shift = b - 64;
            if (MpcCore.decrypt(sign)) {
                result.high = setPublic64(int64(type(uint64).max));
            } else {
                result.high = setPublic64(int64(0));
            }
            result.low = gtInt64.wrap(gtUint64.unwrap(MpcCore.shr(gtUint64.wrap(gtInt64.unwrap(a.high)), shift)));
        } else if (b > 0) {
            uint64 mask = uint64(type(uint64).max >> (64 - b));
            result.low = gtInt64.wrap(gtUint64.unwrap(MpcCore.or(
                MpcCore.shr(gtUint64.wrap(gtInt64.unwrap(a.low)), b),
                MpcCore.shl(MpcCore.and(gtUint64.wrap(gtInt64.unwrap(a.high)), mask), 64 - b)
            )));
            if (MpcCore.decrypt(sign)) {
                uint64 signMask = uint64(type(uint64).max << (64 - b));
                result.high = or(
                    gtInt64.wrap(gtUint64.unwrap(MpcCore.shr(gtUint64.wrap(gtInt64.unwrap(a.high)), b))),
                    setPublic64(int64(signMask))
                );
            } else {
                result.high = gtInt64.wrap(gtUint64.unwrap(MpcCore.shr(gtUint64.wrap(gtInt64.unwrap(a.high)), b)));
            }
        } else {
            result.low = a.low;
            result.high = a.high;
        }
        return result;
    } 

    // =========== signed 256 bit operations ==============

    function validateCiphertext(
        itInt256 memory input
    ) internal returns (gtInt256 memory) {
        gtInt256 memory result;

        itInt128 memory highInput;
        highInput.ciphertext = input.ciphertext.high;
        highInput.signature = input.signature[0];

        itInt128 memory lowInput;
        lowInput.ciphertext = input.ciphertext.low;
        lowInput.signature = input.signature[1];

        result.high = validateCiphertext(highInput);
        result.low = validateCiphertext(lowInput);

        return result;
    }

    function onBoard(ctInt256 memory ct) internal returns (gtInt256 memory) {
        gtInt256 memory result;

        result.high = onBoard(ct.high);
        result.low = onBoard(ct.low);

        return result;
    }

    function offBoard(gtInt256 memory pt) internal returns (ctInt256 memory) {
        ctInt256 memory result;

        result.high = offBoard(pt.high);
        result.low = offBoard(pt.low);

        return result;
    }

    function offBoardToUser(
        gtInt256 memory pt,
        address addr
    ) internal returns (ctInt256 memory) {
        ctInt256 memory result;

        result.high = offBoardToUser(pt.high, addr);
        result.low = offBoardToUser(pt.low, addr);

        return result;
    }

    function offBoardCombined(
        gtInt256 memory pt,
        address addr
    ) internal returns (utInt256 memory) {
        utInt256 memory result;

        result.ciphertext = offBoard(pt);
        result.userCiphertext = offBoardToUser(pt, addr);

        return result;
    }

    function setPublic256(int256 pt) internal returns (gtInt256 memory) {
        gtInt256 memory result;

        // Correctly split the 256-bit value into high and low 128-bit parts
        uint128 low = uint128(uint256(pt));
        int128 high = int128(pt >> 128);

        result.high = setPublic128(high);
        result.low = setPublic128(uint128ToInt128(low));

        return result;
    }

    function decrypt(gtInt256 memory ct) internal returns (int256) {
        int128 highPart = decrypt(ct.high);
        int128 lowPartSigned = decrypt(ct.low);
        uint128 lowPart = int128ToUint128(lowPartSigned);
        // Combine high and low parts properly
        return (int256(highPart) << 128) | int256(int256(uint256(uint128(lowPart))));
    }

    function mux(
        gtBool bit,
        gtInt256 memory a,
        gtInt256 memory b
    ) internal returns (gtInt256 memory) {
        gtInt256 memory result;

        result.low = mux(bit, a.low, b.low);
        result.high = mux(bit, a.high, b.high);

        return result;
    }

    function negate256(gtInt256 memory a) internal returns (gtInt256 memory) {
        gtInt256 memory result;

        // Two's complement negation: ~a + 1
        result.low = xor(a.low, setPublic128(int128(-1)));
        result.high = xor(a.high, setPublic128(int128(-1)));

        // Add 1
        result = add(result, setPublic256(int256(1)));

        return result;
    }

    function add(
        gtInt256 memory a,
        gtInt256 memory b
    ) internal returns (gtInt256 memory) {
        gtInt256 memory result;
        result.low = add(a.low, b.low);
        gtBool carry = isLessThanInt128(result.low, a.low);
        result.high = add(a.high, b.high);
        result.high = mux(
            carry,
            result.high,
            add(result.high, setPublic128(int128(1)))
        );
        return result;
    }

    function sub(
        gtInt256 memory a,
        gtInt256 memory b
    ) internal returns (gtInt256 memory) {
        return add(a, negate256(b));
    }

    function mul(
        gtInt256 memory a,
        gtInt256 memory b
    ) internal returns (gtInt256 memory) {
        gtBool aNegative = lt(a.high, setPublic128(int128(0)));
        gtBool bNegative = lt(b.high, setPublic128(int128(0)));

        gtInt256 memory aAbs = mux(aNegative, a, negate256(a));
        gtInt256 memory bAbs = mux(bNegative, b, negate256(b));

        gtUint256 memory aAbsU = toUint256(aAbs);
        gtUint256 memory bAbsU = toUint256(bAbs);

        gtUint256 memory unsignedResultU = MpcCore.mul(aAbsU, bAbsU);
        gtInt256 memory unsignedResult = fromUint256(unsignedResultU);
        
        gtBool resultNegative = MpcCore.xor(aNegative, bNegative);
        return mux(resultNegative, unsignedResult, negate256(unsignedResult));
    }

    function div(
        gtInt256 memory a,
        gtInt256 memory b
    ) internal returns (gtInt256 memory) {
        int256 aValue = decrypt(a);
        int256 bValue = decrypt(b);
        if (bValue == 0) {
            return setPublic256(int256(0));
        }
        
        // Handle the overflow case: MIN / -1 = -MIN, but -MIN overflows
        // In 2's complement arithmetic, this wraps around to MIN itself
        if (aValue == type(int256).min && bValue == -1) {
            return setPublic256(type(int256).min);
        }
        
        int256 resultValue = aValue / bValue;
        return setPublic256(resultValue);
    }

    function and(
        gtInt256 memory a,
        gtInt256 memory b
    ) internal returns (gtInt256 memory) {
        gtInt256 memory result;
        result.low = and(a.low, b.low);
        result.high = and(a.high, b.high);
        return result;
    }

    function or(
        gtInt256 memory a,
        gtInt256 memory b
    ) internal returns (gtInt256 memory) {
        gtInt256 memory result;
        result.low = or(a.low, b.low);
        result.high = or(a.high, b.high);
        return result;
    }

    function xor(
        gtInt256 memory a,
        gtInt256 memory b
    ) internal returns (gtInt256 memory) {
        gtInt256 memory result;
        result.low = xor(a.low, b.low);
        result.high = xor(a.high, b.high);
        return result;
    }

    function eq(
        gtInt256 memory a,
        gtInt256 memory b
    ) internal returns (gtBool) {
        gtBool lowEqual = eq(a.low, b.low);
        gtBool highEqual = eq(a.high, b.high);
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).And(
                    combineEnumsToBytes3(
                        MPC_TYPE.SBOOL_T,
                        MPC_TYPE.SBOOL_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtBool.unwrap(lowEqual),
                    gtBool.unwrap(highEqual)
                )
            );
    }

    function ne(
        gtInt256 memory a,
        gtInt256 memory b
    ) internal returns (gtBool) {
        gtBool lowNotEqual = ne(a.low, b.low);
        gtBool highNotEqual = ne(a.high, b.high);
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Or(
                    combineEnumsToBytes3(
                        MPC_TYPE.SBOOL_T,
                        MPC_TYPE.SBOOL_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtBool.unwrap(lowNotEqual),
                    gtBool.unwrap(highNotEqual)
                )
            );
    }

    function gt(gtInt256 memory a, gtInt256 memory b) internal returns (gtBool) {
        gtBool highGt = gt(a.high, b.high);
        gtBool highEq = eq(a.high, b.high);
        gtBool lowGt = MpcCore.gt(toUint128(a.low), toUint128(b.low));
        return MpcCore.or(highGt, MpcCore.and(highEq, lowGt));
    }

    function lt(gtInt256 memory a, gtInt256 memory b) internal returns (gtBool) {
        gtBool highLt = lt(a.high, b.high);
        gtBool highEq = eq(a.high, b.high);
        gtBool lowLt = MpcCore.lt(toUint128(a.low), toUint128(b.low));
        return MpcCore.or(highLt, MpcCore.and(highEq, lowLt));
    }

    function ge(gtInt256 memory a, gtInt256 memory b) internal returns (gtBool) {
        gtBool isLt = lt(a, b);
        return MpcCore.not(isLt);
    }

    function le(gtInt256 memory a, gtInt256 memory b) internal returns (gtBool) {
        gtBool isGt = gt(a, b);
        return MpcCore.not(isGt);
    }

    // Helper function to compare gtInt128 values
    function isLessThanInt128(
        gtInt128 memory a,
        gtInt128 memory b
    ) internal returns (gtBool) {
        // Compare high parts as signed 64-bit integers
        gtBool highLt = lt(a.high, b.high);
        gtBool highEq = eq(a.high, b.high);
        // Compare low parts as unsigned 64-bit if high parts are equal
        gtBool lowLt = MpcCore.lt(gtUint64.wrap(gtInt64.unwrap(a.low)), gtUint64.wrap(gtInt64.unwrap(b.low)));
        return MpcCore.or(highLt, MpcCore.and(highEq, lowLt));
    }

    // Helper to convert gtInt128 to gtUint128 (for unsigned comparison)
    function toUint128(gtInt128 memory a) internal pure returns (gtUint128 memory) {
        return gtUint128({
            high: gtUint64.wrap(gtInt64.unwrap(a.high)),
            low: gtUint64.wrap(gtInt64.unwrap(a.low))
        });
    }

    // Helper to convert gtInt256 to gtUint256 (for unsigned comparison)
    function toUint256(gtInt256 memory a) internal pure returns (gtUint256 memory) {
        return gtUint256({
            high: toUint128(a.high),
            low: toUint128(a.low)
        });
    }

    // Helper to convert gtUint256 to gtInt256
    function fromUint256(gtUint256 memory a) internal pure returns (gtInt256 memory) {
        return gtInt256({
            high: fromUint128(a.high),
            low: fromUint128(a.low)
        });
    }

    // Helper to convert gtUint128 to gtInt128
    function fromUint128(gtUint128 memory a) internal pure returns (gtInt128 memory) {
        return gtInt128({
            high: gtInt64.wrap(gtUint64.unwrap(a.high)),
            low: gtInt64.wrap(gtUint64.unwrap(a.low))
        });
    }

    // Helper to reinterpret int128 as uint128 (preserve bits)
    function int128ToUint128(int128 x) internal pure returns (uint128) {
        return uint128(uint256(uint128(x)));
    }
    
    function uint128ToInt128(uint128 x) internal pure returns (int128) {
        return int128(x);
    }
}
