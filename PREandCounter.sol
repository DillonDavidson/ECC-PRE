// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

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
    bytes private c5;

    // Address for the counting contract
    address public countingContractAddress;
    Counter public countingContract;

    // Constructor to initialize contract
    constructor(uint _c1, uint _c2, bytes memory _c3, uint _c4, bytes memory _c5, address[] memory _allowedAddresses)
    {
        c1 = _c1;
        c2 = _c2;
        c3 = _c3;
        c4 = _c4;
        c5 = _c5;
        countingContract = new Counter(address(this), _allowedAddresses);
        countingContractAddress = address(countingContract);
    }

    // Function to re-encrypt the ciphertext with the re-encryption keys
    function ReEncrypt(uint256 _rk1, uint256 _rk2, uint256 _rk3) public returns (uint256, uint256, bytes memory, uint256)
    {
        uint256 _c1_y = EllipticCurve.deriveY(0x02, c1, AA, BB, PP);
        uint256 _c1prime; 
        uint256 _c2prime;
        uint256 _c4prime;
        uint256 __;
        bytes memory _c3prime;


        (_c1prime, __) = EllipticCurve.ecMul(_rk1, c1, _c1_y, AA, PP);

        (_c2prime, __) = EllipticCurve.ecMul(_rk2, c1, _c1_y, AA, PP);

        (_c4prime, __) = EllipticCurve.ecMul(_rk3, c1, _c1_y, AA, PP);

        _c3prime = c3;

        countingContract.increment(msg.sender);
        return (_c1prime, _c2prime, _c3prime, _c4prime);
    }
}

contract Counter
{
    address   private owner;
    address[] private allowedAddresses;  
    mapping(address => uint) public addressCounts;
    
    // Initialize owner and allowed addresses
    constructor(address _owner, address[] memory _allowedAddresses)
    {
        owner = _owner;
        allowedAddresses = _allowedAddresses;
    }

    // Modifier to check if caller is allowed
    function allowedSender(address me) internal view returns (bool)
    {
        bool isAllowed = false;

        for (uint i = 0; i < allowedAddresses.length; i++)
        {
            if (allowedAddresses[i] == me)
            {
                isAllowed = true;
                break;
            }
        }

        return isAllowed;
    }

    // Increment the count
    function increment(address user) public
    {
        require(msg.sender == owner, "Error: invalid sender");
        
        require(allowedSender(user) == true, "Error: invalid sender");
        
        addressCounts[user]++;
    }
    
    // Request the count
    function getCount(address _user) public view returns (uint)
    {
        return addressCounts[_user];
    }
}
