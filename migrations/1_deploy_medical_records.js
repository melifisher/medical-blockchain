const MedicalRecordsRegistry = artifacts.require("MedicalRecordsRegistry");

module.exports = function(deployer) {
  deployer.deploy(MedicalRecordsRegistry);
};