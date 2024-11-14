
npm install -g ganache truffle

//Tener corriendo ganache-cli en segundo plano
ganache-cli

cd medical-blockchain
//Cambiar la url de ganache en .env
//Desplegar el contrato
truffle compile
truffle migrate
//Despues de truffle migrate saldra el contract address para ponerlo en el .env

pip install fastapi uvicorn web3 python-dotenv pydantic eth-account

//iniciar el servicio fastapi
uvicorn blockchain_service:app --reload