// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import "contracts/EllipticCurve.sol";

contract PRE
{
    // SECP256k1 curve constants
    uint public constant PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    // Ciphertext values

    uint private c1;
    uint private c1_y;
    uint private c2;
    uint private c2_y;
    bytes private c3;
    uint private c4;
    uint private c4_y;
    uint private c5p;
    uint8 public parity1;
    uint8 public parity2;
    uint8 public parity4;
    uint private hash;

    // Address for the counting contract
    address public countingContractAddress;
    Counter public countingContract;
    // Constructor to initialize PRE contract
    constructor
    (
        uint _c1_x,
        uint _c1_y,
        uint _c2_x,
        uint _c2_y,
        bytes memory _c3,
        uint _c4_x,
        uint _c4_y,
        uint _c5_times_p,
        bytes32[] memory _allowedAddresses,
        uint24 parity
    )
    {
            c1 = _c1_x;
            c1_y = _c1_y;
            c2 = _c2_x;
            c2_y = _c2_y;
            c3 = _c3;
            c4 = _c4_x;
            c4_y = _c4_y;
            c5p = _c5_times_p;
            parity1 = uint8(parity >> 16);
            parity2 = uint8(parity >> 8);
            parity4 = uint8(parity); 
            hash = uint256(keccak256(abi.encodePacked(c1, c2, c3, c4))) % PP;

        // Concatenate c1, c2, c3, and c4 and hash the result
        countingContract = new Counter(address(this), _allowedAddresses);
        countingContractAddress = address(countingContract);
    }

    function ReEncrypt(uint _rk1, uint _rk2, uint _rk3) public returns (uint, uint, bytes memory, uint)
    {
        uint __;
        uint _c1prime;
        uint _c2prime;
        uint _c4prime;

        (__, _c1prime) = EllipticCurve.ecMul(hash, c2, c2_y, 0, PP);

        (_c4prime, _c2prime) = EllipticCurve.ecAdd(__, _c1prime, c4, c4_y, 0, PP);
        
        require(c5p == _c4prime, "c5P != c4 + h3(c1, c2, c3, c4)c2");

        countingContract.increment(msg.sender);

        (_c1prime, __) = EllipticCurve.ecMul(_rk1, c1, c1_y, 0, PP);

        (_c2prime, __) = EllipticCurve.ecMul(_rk2, c1, c1_y, 0, PP);

        (_c4prime, __) = EllipticCurve.ecMul(_rk3, c1, c1_y, 0, PP);

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
