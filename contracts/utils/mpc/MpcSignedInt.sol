// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "./MpcInterface.sol";
import "./MpcTypes.sol";

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
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Gt(
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

    function lt(gtInt8 a, gtInt8 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Lt(
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

    function ge(gtInt8 a, gtInt8 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Ge(
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

    function le(gtInt8 a, gtInt8 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Le(
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
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Gt(
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

    function lt(gtInt16 a, gtInt16 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Lt(
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

    function ge(gtInt16 a, gtInt16 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Ge(
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

    function le(gtInt16 a, gtInt16 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Le(
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
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Gt(
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

    function lt(gtInt32 a, gtInt32 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Lt(
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

    function ge(gtInt32 a, gtInt32 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Ge(
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

    function le(gtInt32 a, gtInt32 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Le(
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
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Gt(
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

    function lt(gtInt64 a, gtInt64 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Lt(
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

    function ge(gtInt64 a, gtInt64 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Ge(
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

    function le(gtInt64 a, gtInt64 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Le(
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

    function setPublic128(int128 pt) internal returns (gtInt128 memory) {
        gtInt128 memory result;

        // Split the 128-bit value into high and low 64-bit parts
        int64 low = int64(pt);
        int64 high = int64(pt >> 64);

        result.high = setPublic64(high);
        result.low = setPublic64(low);

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
        gtInt128 memory result;

        // For simplicity, we'll use a basic multiplication
        // In a real implementation, you'd want to handle overflow properly
        result.low = mul(a.low, b.low);
        result.high = add(mul(a.high, b.low), mul(a.low, b.high));

        return result;
    }

    function div(
        gtInt128 memory a,
        gtInt128 memory b
    ) internal returns (gtInt128 memory) {
        // Check if numbers are positive (sign bit is 0)
        gtBool aPositive = eq(
            and(a.high, setPublic64(int64(-9223372036854775808))),
            setPublic64(int64(0))
        );

        gtBool bPositive = eq(
            and(b.high, setPublic64(int64(-9223372036854775808))),
            setPublic64(int64(0))
        );

        // Get absolute values
        gtInt128 memory aAbsolute = mux(aPositive, a, negate(a));

        gtInt128 memory bAbsolute = mux(bPositive, b, negate(b));

        // Perform unsigned division on absolute values
        gtInt128 memory divResult = unsignedDiv(aAbsolute, bAbsolute);

        // Determine if result should be negative
        gtBool outputNegative = boolXor(aPositive, bPositive);

        // Apply sign to result
        return mux(outputNegative, negate(divResult), divResult);
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

    function unsignedDiv(
        gtInt128 memory a,
        gtInt128 memory b
    ) internal returns (gtInt128 memory) {
        // Basic long division implementation
        // For simplicity, we'll use a basic approach
        gtInt128 memory result;

        // For now, implement a simple division for low part only
        result.low = div(a.low, b.low);
        result.high = setPublic64(int64(0));

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

    function gt(
        gtInt128 memory a,
        gtInt128 memory b
    ) internal returns (gtBool) {
        gtBool highEqual = eq(a.high, b.high);
        gtBool highGreater = gt(a.high, b.high);
        gtBool lowGreater = gt(a.low, b.low);
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mux(
                    combineEnumsToBytes3(
                        MPC_TYPE.SBOOL_T,
                        MPC_TYPE.SBOOL_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtBool.unwrap(highEqual),
                    gtBool.unwrap(lowGreater),
                    gtBool.unwrap(highGreater)
                )
            );
    }

    function lt(
        gtInt128 memory a,
        gtInt128 memory b
    ) internal returns (gtBool) {
        gtBool highEqual = eq(a.high, b.high);
        gtBool highLess = lt(a.high, b.high);
        gtBool lowLess = lt(a.low, b.low);
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mux(
                    combineEnumsToBytes3(
                        MPC_TYPE.SBOOL_T,
                        MPC_TYPE.SBOOL_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtBool.unwrap(highEqual),
                    gtBool.unwrap(lowLess),
                    gtBool.unwrap(highLess)
                )
            );
    }

    function ge(
        gtInt128 memory a,
        gtInt128 memory b
    ) internal returns (gtBool) {
        gtBool highEqual = eq(a.high, b.high);
        gtBool highGreater = gt(a.high, b.high);
        gtBool lowGreaterOrEqual = ge(a.low, b.low);
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mux(
                    combineEnumsToBytes3(
                        MPC_TYPE.SBOOL_T,
                        MPC_TYPE.SBOOL_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtBool.unwrap(highEqual),
                    gtBool.unwrap(lowGreaterOrEqual),
                    gtBool.unwrap(highGreater)
                )
            );
    }

    function le(
        gtInt128 memory a,
        gtInt128 memory b
    ) internal returns (gtBool) {
        gtBool highEqual = eq(a.high, b.high);
        gtBool highLess = lt(a.high, b.high);
        gtBool lowLessOrEqual = le(a.low, b.low);
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mux(
                    combineEnumsToBytes3(
                        MPC_TYPE.SBOOL_T,
                        MPC_TYPE.SBOOL_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtBool.unwrap(highEqual),
                    gtBool.unwrap(lowLessOrEqual),
                    gtBool.unwrap(highLess)
                )
            );
    }

    function decrypt(gtInt128 memory ct) internal returns (int128) {
        int64 highPart = decrypt(ct.high);
        int64 lowPart = decrypt(ct.low);

        // Combine high and low parts properly
        return (int128(highPart) << 64) | int128(int64(uint64(lowPart)));
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

        // Split the 256-bit value into high and low 128-bit parts
        int128 low = int128(pt);
        int128 high = int128(pt >> 128);

        result.high = setPublic128(high);
        result.low = setPublic128(low);

        return result;
    }

    function add(
        gtInt256 memory a,
        gtInt256 memory b
    ) internal returns (gtInt256 memory) {
        gtInt256 memory result;

        // Add low parts
        result.low = add(a.low, b.low);

        // Check if there's a carry from low addition using comparison helper
        gtBool carry = isLessThanInt128(result.low, a.low);

        // Add high parts with carry if needed
        result.high = add(a.high, b.high);

        // Add carry to high part if needed
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
        gtInt256 memory result;

        // Subtract low parts
        result.low = sub(a.low, b.low);

        // Check if there's a borrow from low subtraction
        gtBool borrow = isLessThanInt128(a.low, b.low);

        // Subtract high parts with borrow if needed
        result.high = sub(a.high, b.high);

        // Subtract borrow from high part if needed
        result.high = mux(
            borrow,
            result.high,
            sub(result.high, setPublic128(int128(1)))
        );

        return result;
    }

    function mul(
        gtInt256 memory a,
        gtInt256 memory b
    ) internal returns (gtInt256 memory) {
        gtInt256 memory result;

        // For simplicity, we'll use a basic multiplication
        // In a real implementation, you'd want to handle overflow properly
        result.low = mul(a.low, b.low);
        result.high = add(mul(a.high, b.low), mul(a.low, b.high));

        return result;
    }

    function div(
        gtInt256 memory a,
        gtInt256 memory b
    ) internal returns (gtInt256 memory) {
        // Check if numbers are positive (sign bit is 0)
        gtBool aPositive = eq(
            and(a.high.high, setPublic64(int64(-9223372036854775808))),
            setPublic64(int64(0))
        );

        gtBool bPositive = eq(
            and(b.high.high, setPublic64(int64(-9223372036854775808))),
            setPublic64(int64(0))
        );

        // Get absolute values
        gtInt256 memory aAbsolute = mux(aPositive, a, negate256(a));

        gtInt256 memory bAbsolute = mux(bPositive, b, negate256(b));

        // Perform unsigned division on absolute values
        gtInt256 memory divResult = unsignedDiv256(aAbsolute, bAbsolute);

        // Determine if result should be negative
        gtBool outputNegative = boolXor(aPositive, bPositive);

        // Apply sign to result
        return mux(outputNegative, negate256(divResult), divResult);
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

    function unsignedDiv256(
        gtInt256 memory a,
        gtInt256 memory b
    ) internal returns (gtInt256 memory) {
        // Basic long division implementation
        // For simplicity, we'll use a basic approach
        gtInt256 memory result;

        // For now, implement a simple division for low part only
        result.low = unsignedDiv(a.low, b.low);
        result.high = setPublic128(int128(0));

        return result;
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

    function gt(
        gtInt256 memory a,
        gtInt256 memory b
    ) internal returns (gtBool) {
        gtBool highEqual = eq(a.high, b.high);
        gtBool highGreater = gt(a.high, b.high);
        gtBool lowGreater = gt(a.low, b.low);
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mux(
                    combineEnumsToBytes3(
                        MPC_TYPE.SBOOL_T,
                        MPC_TYPE.SBOOL_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtBool.unwrap(highEqual),
                    gtBool.unwrap(lowGreater),
                    gtBool.unwrap(highGreater)
                )
            );
    }

    function lt(
        gtInt256 memory a,
        gtInt256 memory b
    ) internal returns (gtBool) {
        gtBool highEqual = eq(a.high, b.high);
        gtBool highLess = lt(a.high, b.high);
        gtBool lowLess = lt(a.low, b.low);
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mux(
                    combineEnumsToBytes3(
                        MPC_TYPE.SBOOL_T,
                        MPC_TYPE.SBOOL_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtBool.unwrap(highEqual),
                    gtBool.unwrap(lowLess),
                    gtBool.unwrap(highLess)
                )
            );
    }

    function ge(
        gtInt256 memory a,
        gtInt256 memory b
    ) internal returns (gtBool) {
        gtBool highEqual = eq(a.high, b.high);
        gtBool highGreater = gt(a.high, b.high);
        gtBool lowGreaterOrEqual = ge(a.low, b.low);
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mux(
                    combineEnumsToBytes3(
                        MPC_TYPE.SBOOL_T,
                        MPC_TYPE.SBOOL_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtBool.unwrap(highEqual),
                    gtBool.unwrap(lowGreaterOrEqual),
                    gtBool.unwrap(highGreater)
                )
            );
    }

    function le(
        gtInt256 memory a,
        gtInt256 memory b
    ) internal returns (gtBool) {
        gtBool highEqual = eq(a.high, b.high);
        gtBool highLess = lt(a.high, b.high);
        gtBool lowLessOrEqual = le(a.low, b.low);
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mux(
                    combineEnumsToBytes3(
                        MPC_TYPE.SBOOL_T,
                        MPC_TYPE.SBOOL_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtBool.unwrap(highEqual),
                    gtBool.unwrap(lowLessOrEqual),
                    gtBool.unwrap(highLess)
                )
            );
    }

    function decrypt(gtInt256 memory ct) internal returns (int256) {
        int128 highPart = decrypt(ct.high);
        int128 lowPart = decrypt(ct.low);

        // Combine high and low parts properly
        return (int256(highPart) << 128) | int256(int128(uint128(lowPart)));
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

    // Helper function to compare gtInt128 values
    function isLessThanInt128(
        gtInt128 memory a,
        gtInt128 memory b
    ) internal returns (gtBool) {
        gtBool highEqual = eq(a.high, b.high);
        gtBool highLess = gtBool.wrap(
            ExtendedOperations(address(MPC_PRECOMPILE)).Lt(
                combineEnumsToBytes3(
                    MPC_TYPE.SUINT64_T,
                    MPC_TYPE.SUINT64_T,
                    ARGS.BOTH_SECRET
                ),
                gtInt64.unwrap(a.high),
                gtInt64.unwrap(b.high)
            )
        );
        gtBool lowLess = gtBool.wrap(
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
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mux(
                    combineEnumsToBytes3(
                        MPC_TYPE.SBOOL_T,
                        MPC_TYPE.SBOOL_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtBool.unwrap(highEqual),
                    gtBool.unwrap(lowLess),
                    gtBool.unwrap(highLess)
                )
            );
    }
}
