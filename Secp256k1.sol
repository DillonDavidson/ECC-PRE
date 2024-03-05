// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "contracts/EllipticCurve.sol";

/**
 ** @title Secp256k1 Elliptic Curve
 ** @notice Example of particularization of Elliptic Curve for secp256k1 curve
 ** @author Witnet Foundation
 */
contract Secp256k1
{
    uint256 public constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 public constant AA = 0;
    uint256 public constant BB = 7;
    uint256 public constant PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 public constant NN = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
    uint256 public alice_sk = 0;
    uint256 public bob_sk = 0;
    uint256 public charlie_sk = 0;
    /// @notice Public Key derivation from private key
    /// Warning: this is just an example. Do not expose your private key.
    /// @param privKey The private key
    /// @return (qx, qy) The Public Key
    function derivePubKey(uint256 privKey) public pure returns (uint256, uint256)
    {
        return EllipticCurve.ecMul(privKey, GX, GY, AA, PP);
    }

    function setAliceSKey(uint256 sk_) public 
    {
        alice_sk = sk_;
    }

    function setBobSKey(uint256 sk_) public 
    {
        bob_sk = sk_;
    }

    function setCharlieSKey(uint256 sk_) public 
    {
        charlie_sk = sk_;
    }

    function getAlicePubKey() public view returns (uint256, uint256)
    {
        return derivePubKey(alice_sk);
    }

    function getBobPubKey() public view returns (uint256, uint256)
    {
        return derivePubKey(bob_sk);
    }

    function getCharliePubKey() public view returns (uint256, uint256)
    {
        return derivePubKey(charlie_sk);
    }

    function makeProxyKey(uint256 sk_, uint256 pk_x_, uint256 pk_y_) external pure returns (uint256, uint256)
    {
        // Calculate inverse of Alice's secret key
        uint256 sk_inverse = EllipticCurve.invMod(sk_, NN);
        
        // Re-Encryption Key = Inverse(Alice's secret key) * Bob's public key
        (uint256 re_x_, uint256 re_y_) = EllipticCurve.ecMul(sk_inverse, pk_x_, pk_y_, AA, PP);
        
        // Return re-encryption key
        return (re_x_, re_y_);
    }

    function combineKeys(uint256 aToB_x, uint256 aToB_y, uint256 bToC_x, uint256 bToC_y) external view returns (uint256, uint256)
    {
       // Calculate inverse of Alice to Bob secret key
        uint256 skInverse_AtoB = EllipticCurve.invMod(alice_sk, NN);

        // Calculate inverse of Bob to Charlie secret key
        uint256 skInverse_BtoC = EllipticCurve.invMod(bob_sk, NN);

        (uint256 new1x, uint256 new1y) = EllipticCurve.ecMul(skInverse_AtoB, bToC_x, bToC_y, AA, PP);
        (uint256 new2x, uint256 new2y) = EllipticCurve.ecMul(skInverse_BtoC, aToB_x, aToB_y, AA, PP);

        // Re-Encryption Key from Alice to Charlie = Inverse(Alice to Bob secret key) * (Re-Encryption Key from Bob to Charlie)
        (uint256 re_x, uint256 re_y) = EllipticCurve.ecAdd(new1x, new1y, new2x, new2y, AA, PP);
        
        // Return combined re-encryption key
        return (re_x, re_y);
    }

    function removingTheInverse() public view returns (uint256, uint256)
    {
        uint256 skInverse = EllipticCurve.invMod(alice_sk, NN);
        (uint256 bx, uint256 by) = derivePubKey(bob_sk);
        
        // a^(-1) * bG
        (uint256 newx, uint256 newy) = EllipticCurve.ecMul(skInverse, bx, by, AA, PP);

        // try to undo it
        return EllipticCurve.ecMul(alice_sk, newx, newy, AA, PP);
    }
}
