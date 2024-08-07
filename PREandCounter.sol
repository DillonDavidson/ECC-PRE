        // SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import "contracts/EllipticCurve.sol";

contract PRE
{
    // SECP256k1 curve constants
    uint256 public constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 public constant AA = 0;
    uint256 public constant BB = 7;
    uint256 public constant PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 public constant NN = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;

    // Ciphertext values
    uint private c1;
    uint private c2;
    bytes private c3;
    uint private c4;
    uint private c5p;

    // Address for the counting contract
    address public countingContractAddress;
    Counter public countingContract;

    uint8 private parity1;
    uint8 private parity2;
    uint8 private parity4;

    uint256 private hash;
    uint256 public dumb_c2_y;
    uint256 public dumb_c4_y;
    uint256 public hashc2_x;
    uint256 public hashc2_y;
    uint256 public hash2c4_x;
    uint256 public hash2c4_y;
    uint256 public c2y;
    uint256 public c4y;

    // Constructor to initialize contract
    // What if we send _c5P's X
    constructor(uint _c1_x, uint _c2_x, bytes memory _c3, uint _c4_x, uint _c5_times_p, bytes32[] memory _allowedAddresses, uint _c2_y, uint _c4_y, uint8 pari1, uint8 pari2, uint8 pari4)
    {
        c1 = _c1_x;
        c2 = _c2_x;
        c3 = _c3;
        c4 = _c4_x;
        c5p = _c5_times_p;

        c2y = _c2_y;
        c4y = _c4_y;

        parity1 = pari1;
        parity2 = pari2;
        parity4 = pari4;

        // Concatenate c1, c2, c3, and c4 and hash the result
        hash = uint256(keccak256(abi.encodePacked(c1, c2, c3, c4))) % PP;

        countingContract = new Counter(address(this), _allowedAddresses);
        countingContractAddress = address(countingContract);
    }

    function TEST() public returns(uint256, uint256, uint256, uint256)
    {
        dumb_c2_y =  EllipticCurve.deriveY(parity2, c2, AA, BB, PP);
        dumb_c4_y =  EllipticCurve.deriveY(parity4, c4, AA, BB, PP);

        (hashc2_x, hashc2_y) = EllipticCurve.ecMul(hash, c2, dumb_c2_y, AA, PP);
        (hash2c4_x, hash2c4_y) = EllipticCurve.ecAdd(hashc2_x, hashc2_y, c4, dumb_c4_y, AA, PP);

        return (hashc2_x, hashc2_y, hash2c4_x, hash2c4_y);
    }

    function ReEncrypt(uint256 _rk1, uint256 _rk2, uint256 _rk3) public returns (uint256, uint256, bytes memory, uint256)
    {
        countingContract.increment(msg.sender);

        uint256 __;
        uint256 _c1prime;
        uint256 _c2prime;
        uint256 _c4prime;
        uint256 _c2_y = EllipticCurve.deriveY(parity2, c2, AA, BB, PP);
        uint256 _c4_y = EllipticCurve.deriveY(parity4, c4, AA, BB, PP);

        (__, _c1prime) = EllipticCurve.ecMul(hash, c2, _c2_y, AA, PP);
        (_c4prime, _c2prime) = EllipticCurve.ecAdd(__, _c1prime, c4, _c4_y, AA, PP);
        
        require(c5p == _c4prime, "c5P != c4 + h3(c1, c2, c3, c4)c2");

        uint256 _c1_y = EllipticCurve.deriveY(parity1, c1, AA, BB, PP);

        (_c1prime, __) = EllipticCurve.ecMul(_rk1, c1, _c1_y, AA, PP);

        (_c2prime, __) = EllipticCurve.ecMul(_rk2, c1, _c1_y, AA, PP);

        (_c4prime, __) = EllipticCurve.ecMul(_rk3, c1, _c1_y, AA, PP);

        return (_c1prime, _c2prime, c3, _c4prime);
    }
}

contract Counter
{
    address   private owner;
    bytes32[] private allowedAddresses;
    mapping(address => uint) public addressCounts;

    // Initialize owner and allowed addresses
    constructor(address _owner, bytes32[] memory _allowedAddresses)
    //constructor(address _owner)
    {
        owner = _owner;
        allowedAddresses = _allowedAddresses;
    }

    // Modifier to check if caller is allowed
    function allowedSender(address me) internal view returns (bool)
    {
        bytes32 hash = keccak256(abi.encodePacked(me));

        for (uint i = 0; i < allowedAddresses.length; i++)
        {
            if (allowedAddresses[i] == hash)
            {
                return true;
            }
        }

        return false;
    }

    // Increment the count
    function increment(address user) public
    {
        require(msg.sender == owner, "Error: invalid sender");

        require(allowedSender(user) == true, "Error: invalid user");

        addressCounts[user]++;
    }

    // Request the count
    function getCount(address _user) public view returns (uint)
    {
        return addressCounts[_user];
    }
}
