# blockchain_service.py
from web3 import Web3
from eth_account.messages import encode_defunct
import json
import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any 
from hexbytes import HexBytes

class BlockchainConfig:
    # Conexión a Ganache
    WEB3_PROVIDER = "http://127.0.0.1:8545"
    
    # Cargar ABI del contrato
    contract_path = os.path.join(
        os.path.dirname(__file__),
        'build/contracts/MedicalRecordsRegistry.json'
    )
    with open(contract_path) as f:
        contract_data = json.load(f)
        CONTRACT_ABI = contract_data['abi']
        
    # La dirección del contrato se obtiene después del deployment
    CONTRACT_ADDRESS = '0x2390B8154c79525ac65dC96a276B3235fE3c91Cf'

class BlockchainService:
    def __init__(self):
        # Conectar a Ganache
        self.w3 = Web3(Web3.HTTPProvider(BlockchainConfig.WEB3_PROVIDER))
        
        # Verificar conexión
        if not self.w3.is_connected():
            raise Exception("No se pudo conectar a Ganache")
        
        # Cargar contrato
        self.contract = self.w3.eth.contract(
            address=BlockchainConfig.CONTRACT_ADDRESS,
            abi=BlockchainConfig.CONTRACT_ABI
        )
        
        # Obtener cuentas de Ganache
        self.accounts = self.w3.eth.accounts


    def sign_document(self, document_hash: bytes, private_key: str) -> str:
        """
        Firma digitalmente un documento utilizando una clave privada.

        Args:
            document_hash (bytes): Hash del documento a firmar.
            private_key (str): Clave privada de la cuenta que firmará el documento.

        Returns:
            str: Firma digital en formato hexadecimal
        """
        # Convertir el hash a bytes si es necesario
        if isinstance(document_hash, str):
            if document_hash.startswith('0x'):
                document_hash = bytes.fromhex(document_hash[2:])
            else:
                document_hash = bytes.fromhex(document_hash)

        # Crear mensaje para firmar
        message = encode_defunct(primitive=document_hash)
        
        # Firmar el mensaje
        signed_message = self.w3.eth.account.sign_message(message, private_key=private_key)
        
        return signed_message.signature

    def verify_signature(self, document_hash: bytes) -> bool:
        """
        Verifica la firma digital de un documento.

        Args:
            document_hash (bytes): Hash del documento a verificar.
            
        Returns:
            bool: Verdadero si la firma es válida, Falso en caso contrario.
        """
        try:
            # Convertir el hash a bytes si es necesario
            if isinstance(document_hash, str):
                if document_hash.startswith('0x'):
                    document_hash = bytes.fromhex(document_hash[2:])
                else:
                    document_hash = bytes.fromhex(document_hash)

            # Llamar a la función de verificación del contrato
            return self.contract.functions.verifySignature(document_hash).call()
        except Exception as e:
            print(f"Error verifying signature: {str(e)}")
            return False

    def register_medical_record(self, content: str, doctor_address: str, doctor_private_key: str):
        """
        Registra un nuevo registro médico con firma digital.
        
        Args:
            content (str): Contenido del documento
            doctor_address (str): Dirección del doctor
            doctor_private_key (str): Clave privada del doctor para firmar
            
        Returns:
            dict: Resultado de la transacción
        """
        try:
            # Calcular hash del documento
            document_hash = self.w3.solidity_keccak(['string'], [content])
            
            # Verificar si el doctor está autorizado
            is_authorized = self.contract.functions.isDoctorAuthorized(
                doctor_address
            ).call()
            
            if not is_authorized:
                raise Exception("Doctor no autorizado")
            
            # Firmar el documento
            signature = self.sign_document(document_hash.hex(), doctor_private_key)
            
            # Construir transacción
            transaction = self.contract.functions.registerRecord(
                document_hash,
                signature
            ).build_transaction({
                'from': doctor_address,
                'gas': 2000000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(doctor_address)
            })
            
            # Firmar y enviar transacción
            """ signed_txn = self.w3.eth.account.sign_transaction(
                transaction_dict=transaction,
                private_key=doctor_private_key
            ) """

            # Send the raw transaction bytes
            tx_hash = self.w3.eth.send_transaction(transaction)
        
            # Esperar confirmación
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            return {
                'status': 'success',
                'document_hash': document_hash.hex(),
                'transaction_hash': receipt['transactionHash'].hex(),
                'block_number': receipt['blockNumber'],
                'doctor_address': doctor_address,
                'signature': HexBytes(signature).hex()
            }
            
        except Exception as e:
            raise Exception(f"Error al registrar registro médico: {str(e)}")
            
    def verify_record(self, document_hash: str):
        """
        Verifica un registro médico y su firma digital.
        
        Args:
            document_hash (str): Hash del documento en formato hexadecimal
            
        Returns:
            dict: Información del registro y estado de verificación
        """
        try:
            print(f"document_hash: {document_hash}")
            # Convertir string hash a bytes si es necesario
            if isinstance(document_hash, str):
                if document_hash.startswith('0x'):
                    document_hash = bytes.fromhex(document_hash[2:])
                else:
                    document_hash = bytes.fromhex(document_hash)
            
            # Obtener registro
            doctor, timestamp, signature, is_valid = self.contract.functions.getRecord(
                document_hash
            ).call()

            # Verificar firma
            is_signature_valid = self.contract.functions.verifySignature(
                document_hash
            ).call()
            
            return {
                'exists': is_valid,
                'doctor': doctor,
                'timestamp': timestamp,
                'signature': HexBytes(signature).hex(),
                'is_signature_valid': is_signature_valid
            }
            
        except Exception as e:
            raise Exception(f"Error al verificar registro: {str(e)}")
            
    def authorize_doctor(self, doctor_address: str, admin_address: str):
        try:
            transaction = self.contract.functions.authorizeDoctor(
                doctor_address
            ).build_transaction({
                'from': admin_address,
                'gas': 2000000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(admin_address)
            })
            
            tx_hash = self.w3.eth.send_transaction(transaction)
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            return {
                'status': 'success',
                'transaction_hash': receipt['transactionHash'].hex(),
                'doctor_address': doctor_address
            }
            
        except Exception as e:
            raise Exception(f"Error al autorizar doctor: {str(e)}")

    def document_hash(self, data: str) -> str:
        try:
            document_hash = self.w3.solidity_keccak(['string'], [data])
            return {
                'status': 'success',
                'document_hash': document_hash.hex()
            }
        except Exception as e:
            raise Exception(f"Error al crear hash: {str(e)}")


# FastAPI endpoints
app = FastAPI()

class RecordRequest(BaseModel):
    content: str
    doctor_address: str
    doctor_private_key: str

class VerifyRequest(BaseModel):
    document_hash: str

class AuthorizeRequest(BaseModel):
    doctor_address: str
    admin_address: str

class AnalysisDataHash(BaseModel):
    nombre: str
    apellidos: str
    resultado: str
    fecha: str
    observaciones: str
    interpretacion: str
    detalles: str

@app.post("/register")
async def register_record(request: RecordRequest):
    service = BlockchainService()
    try:
        result = service.register_medical_record(
            request.content,
            request.doctor_address,
            request.doctor_private_key
        )
        print(result)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/verify/{document_hash}")
async def verify_record(document_hash: str):
    service = BlockchainService()
    try:
        result = service.verify_record(document_hash)
        print(result)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/authorize")
async def authorize_doctor(request: AuthorizeRequest):
    service = BlockchainService()
    try:
        result = service.authorize_doctor(
            request.doctor_address,
            request.admin_address
        )
        print(result)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/hash")
async def document_hash(analysis_data: str):
    service = BlockchainService()
    try:
        result = service.document_hash(analysis_data)
        print(result)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
