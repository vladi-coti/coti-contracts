// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract SignedIntegerTestsContract {
    struct AllGTCastingValues {
        gtInt8 a8_s;
        gtInt8 b8_s;
        // gtInt16 a16_s;
        // gtInt16 b16_s;
        // gtInt32 a32_s;
        // gtInt32 b32_s;
        // gtInt64 a64_s;
        // gtInt64 b64_s;
    }

    int8 public validateResult;
    int8 public addResult;
    int8 public subResult;
    int8 public mulResult;
    int8 public divResult;
    int8 public andResult;
    int8 public orResult;
    int8 public xorResult;
    bool public eqResult;
    bool public neResult;
    bool public gtResult;
    bool public ltResult;
    bool public geResult;
    bool public leResult;
    ctInt8 public offBoardResult;
    ctInt8 public offBoardToUserResult;
    utInt8 public offBoardCombinedResult;
    int8 public onBoardResult1;
    int8 public onBoardResult2;

    // Reset function to clear all state and potentially help with state pollution
    function resetState() public {
        validateResult = 0;
        addResult = 0;
        subResult = 0;
        mulResult = 0;
        divResult = 0;
        andResult = 0;
        orResult = 0;
        xorResult = 0;
        eqResult = false;
        neResult = false;
        gtResult = false;
        ltResult = false;
        geResult = false;
        leResult = false;
        onBoardResult1 = 0;
        onBoardResult2 = 0;
        // Note: offBoardResult, offBoardToUserResult, offBoardCombinedResult 
        // are complex types and harder to reset cleanly
    }

    function validateCiphertextTest(itInt8 calldata value) public {
        validateResult = MpcCore.decrypt(MpcCore.validateCiphertext(value));
    }

    function addTest(int8 a, int8 b) public {
        AllGTCastingValues memory castingValues;

        castingValues.a8_s = MpcCore.setPublic8(a);
        castingValues.b8_s = MpcCore.setPublic8(b);

        int8 result = MpcCore.decrypt(
            MpcCore.add(castingValues.a8_s, castingValues.b8_s)
        );
        addResult = result;
    }

    function subTest(int8 a, int8 b) public {
        AllGTCastingValues memory castingValues;

        castingValues.a8_s = MpcCore.setPublic8(a);
        castingValues.b8_s = MpcCore.setPublic8(b);

        int8 result = MpcCore.decrypt(
            MpcCore.sub(castingValues.a8_s, castingValues.b8_s)
        );
        subResult = result;
    }

    function mulTest(int8 a, int8 b) public {
        AllGTCastingValues memory castingValues;

        castingValues.a8_s = MpcCore.setPublic8(a);
        castingValues.b8_s = MpcCore.setPublic8(b);

        int8 result = MpcCore.decrypt(
            MpcCore.mul(castingValues.a8_s, castingValues.b8_s)
        );
        mulResult = result;
    }

    function divTest(int8 a, int8 b) public {
        AllGTCastingValues memory castingValues;

        castingValues.a8_s = MpcCore.setPublic8(a);
        castingValues.b8_s = MpcCore.setPublic8(b);

        int8 result = MpcCore.decrypt(
            MpcCore.div(castingValues.a8_s, castingValues.b8_s)
        );
        divResult = result;
    }

    function andTest(int8 a, int8 b) public {
        AllGTCastingValues memory castingValues;

        castingValues.a8_s = MpcCore.setPublic8(a);
        castingValues.b8_s = MpcCore.setPublic8(b);

        int8 result = MpcCore.decrypt(
            MpcCore.and(castingValues.a8_s, castingValues.b8_s)
        );
        andResult = result;
    }

    function orTest(int8 a, int8 b) public {
        AllGTCastingValues memory castingValues;

        castingValues.a8_s = MpcCore.setPublic8(a);
        castingValues.b8_s = MpcCore.setPublic8(b);

        int8 result = MpcCore.decrypt(
            MpcCore.or(castingValues.a8_s, castingValues.b8_s)
        );
        orResult = result;
    }

    function xorTest(int8 a, int8 b) public {
        AllGTCastingValues memory castingValues;

        castingValues.a8_s = MpcCore.setPublic8(a);
        castingValues.b8_s = MpcCore.setPublic8(b);

        int8 result = MpcCore.decrypt(
            MpcCore.xor(castingValues.a8_s, castingValues.b8_s)
        );
        xorResult = result;
    }

    function eqTest(int8 a, int8 b) public {
        AllGTCastingValues memory castingValues;

        castingValues.a8_s = MpcCore.setPublic8(a);
        castingValues.b8_s = MpcCore.setPublic8(b);

        bool result = MpcCore.decrypt(
            MpcCore.eq(castingValues.a8_s, castingValues.b8_s)
        );
        eqResult = result;
    }

    function neTest(int8 a, int8 b) public {
        AllGTCastingValues memory castingValues;

        castingValues.a8_s = MpcCore.setPublic8(a);
        castingValues.b8_s = MpcCore.setPublic8(b);

        bool result = MpcCore.decrypt(
            MpcCore.ne(castingValues.a8_s, castingValues.b8_s)
        );
        neResult = result;
    }

    function gtTest(int64 a, int64 b) public {
        gtResult = false;
        gtInt64 gtA = MpcCore.setPublic64(a);
        gtInt64 gtB = MpcCore.setPublic64(b);

        gtBool result = MpcCore.gt(gtA, gtB);
        gtResult = MpcCore.decrypt(result);
    }

    function ltTest(int64 a, int64 b) public {
        ltResult = false;
        gtInt64 gtA = MpcCore.setPublic64(a);
        gtInt64 gtB = MpcCore.setPublic64(b);

        gtBool result = MpcCore.lt(gtA, gtB);
        ltResult = MpcCore.decrypt(result);
    }

    function geTest(int64 a, int64 b) public {
        geResult = false;
        gtInt64 gtA = MpcCore.setPublic64(a);
        gtInt64 gtB = MpcCore.setPublic64(b);

        gtBool result = MpcCore.ge(gtA, gtB);
        geResult = MpcCore.decrypt(result);
    }

    function leTest(int64 a, int64 b) public {
        leResult = false;
        gtInt64 gtA = MpcCore.setPublic64(a);
        gtInt64 gtB = MpcCore.setPublic64(b);

        gtBool result = MpcCore.le(gtA, gtB);
        leResult = MpcCore.decrypt(result);
    }

    function offBoardTest(int8 a, int8 b, int8 c) public {
        offBoardResult = MpcCore.offBoard(MpcCore.setPublic8(a));
        offBoardToUserResult = MpcCore.offBoardToUser(
            MpcCore.setPublic8(b),
            msg.sender
        );
        offBoardCombinedResult = MpcCore.offBoardCombined(
            MpcCore.setPublic8(c),
            msg.sender
        );
    }

    function onBoardTest() public {
        onBoardResult1 = MpcCore.decrypt(MpcCore.onBoard(offBoardResult));
        onBoardResult2 = MpcCore.decrypt(
            MpcCore.onBoard(offBoardCombinedResult.ciphertext)
        );
    }
}
