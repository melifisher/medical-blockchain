// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract MedicalRecordsRegistry {

    struct MedicalRecord {
        bytes32 documentHash;
        address doctor;
        uint256 timestamp;
        bytes signature;
        bool isValid;
    }
    
    mapping(bytes32 => MedicalRecord) private records;
    mapping(address => bool) private authorizedDoctors;
    
    event RecordRegistered(
        bytes32 indexed documentHash,
        address indexed doctor,
        uint256 timestamp,
        bytes signature
    );
    
    constructor() {
        authorizedDoctors[msg.sender] = true; // El deployer es el primer doctor autorizado
    }
    
    modifier onlyAuthorizedDoctor() {
        require(authorizedDoctors[msg.sender], "Not an authorized doctor");
        _;
    }
    
    function authorizeDoctor(address doctor) public onlyAuthorizedDoctor {
        authorizedDoctors[doctor] = true;
    }

    // Función auxiliar para recuperar la dirección del firmante
    function recoverSigner(bytes32 documentHash, bytes memory signature) 
        public 
        pure 
        returns (address)
    {
        bytes32 messageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", documentHash));
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);
        return ecrecover(messageHash, v, r, s);
    }

    // Función auxiliar para dividir la firma en sus componentes
    function splitSignature(bytes memory sig)
        internal
        pure
        returns (bytes32 r, bytes32 s, uint8 v)
    {
        require(sig.length == 65, "Invalid signature length");

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        // Ajuste de la versión para compatibilidad con la firma de ethereum
        if (v < 27) {
            v += 27;
        }

        require(v == 27 || v == 28, "Invalid signature v value");
        return (r, s, v);
    }

    function registerRecord(bytes32 _documentHash, bytes memory _signature) 
        public 
        onlyAuthorizedDoctor 
    {
        require(!records[_documentHash].isValid, "Record already exists");
        
        // Verificar que la firma corresponde al doctor
        address signer = recoverSigner(_documentHash, _signature);
        require(signer == msg.sender, "Invalid signature");
        
        records[_documentHash] = MedicalRecord({
            documentHash: _documentHash,
            doctor: msg.sender,
            timestamp: block.timestamp,
            signature: _signature,
            isValid: true
        });
        
        emit RecordRegistered(
            _documentHash,
            msg.sender,
            block.timestamp,
            _signature
        );
    }
    
    function getRecord(bytes32 _documentHash) 
        public 
        view 
        returns (
            address doctor,
            uint256 timestamp,
            bytes memory signature,
            bool isValid
        ) 
    {
        MedicalRecord memory record = records[_documentHash];
        return (
            record.doctor,
            record.timestamp,
            record.signature,
            record.isValid
        );
    }
    
    function isDoctorAuthorized(address doctor) public view returns (bool) {
        return authorizedDoctors[doctor];
    }

    function verifySignature(bytes32 _documentHash)
        public
        view
        returns (bool isValid)
    {
        MedicalRecord memory record = records[_documentHash];
        if (!record.isValid) {
            return false;
        }

        address signer = recoverSigner(_documentHash, record.signature);
        return signer == record.doctor && authorizedDoctors[signer];
    }
}
