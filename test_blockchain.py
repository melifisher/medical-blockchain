# test_blockchain.py
import requests
import json

def test_medical_records():
    BASE_URL = "http://localhost:8080"
    
    # Obtener cuentas de Ganache (asumiendo que son las primeras dos)
    from web3 import Web3
    w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
    admin_address = w3.eth.accounts[0]
    doctor_address = w3.eth.accounts[2]
    #0x5dC27301647601Db1d07Bd7debe2A69F9bC1a743
    # En Ganache, las llaves privadas se pueden obtener directamente
    # Nota: Esto solo funciona en entornos de desarrollo con Ganache
    # admin_private_key = w3.eth.account.from_key(w3.geth.personal.list_wallets()[0]['privateKey']).privateKey.hex()
    # doctor_private_key = '0x89a1d4aeae91f63c68c80b026ca9f7813872e79'
    doctor_private_key = '0x481dfa18fe66d3cbfc33bf3ec7fe28e774318d944d39a9bbed595664c4276171'

    # 1. Autorizar nuevo doctor
    print("Autorizando doctor...")
    response = requests.post(
        f"{BASE_URL}/authorize",
        json={
            "doctor_address": doctor_address,
            "admin_address": admin_address
        }
    )
    print(response.json())
    
    # 2. Registrar nuevo registro médico
    print("\nRegistrando registro médico...")
    try:
        response = requests.post(
            f"{BASE_URL}/register",
            json={
                "content": "Resultado análisis sangre: Glucosa 95mg/dL",
                "doctor_address": doctor_address,
                "doctor_private_key": doctor_private_key
            }
        )
        result = response.json()
        print(result)
        
        # 3. Verificar el registro
        print("\nVerificando registro...")
        response = requests.get(
            f"{BASE_URL}/verify/{result["document_hash"]}"
        )
        print(response.json())
    except Exception as e:
        print(f"Error en el proceso: {str(e)}")

if __name__ == "__main__":
    test_medical_records()