import subprocess
import json
import platform
import tempfile

def run_slither(contract_code):
    """Run Slither for static analysis."""
    report_file = "report.json"
    try:
        # Create a temporary file for the contract code
        with tempfile.NamedTemporaryFile(delete=False, suffix=".sol") as tmp_file:
            tmp_file.write(contract_code.encode())
            tmp_file.close()
            result = subprocess.run(
                ["slither", tmp_file.name, "--json", report_file],
                capture_output=True, text=True
            )
            if os.path.exists(report_file):
                with open(report_file, "r") as file:
                    report = json.load(file)
                return report
            else:
                return {"error": f"Slither output file not found: {report_file}"}
    except Exception as e:
        return {"error": f"Slither analysis failed: {str(e)}"}

def run_mythril(contract_code):
    """Run Mythril for symbolic execution."""
    try:
        # Create a temporary file for the contract code
        with tempfile.NamedTemporaryFile(delete=False, suffix=".sol") as tmp_file:
            tmp_file.write(contract_code.encode())
            tmp_file.close()
            result = subprocess.run(
                ["myth", "analyze", tmp_file.name, "-o", "json"],
                capture_output=True, text=True
            )
            return json.loads(result.stdout) if result.stdout else {"error": "No Mythril output"}
    except Exception as e:
        return {"error": f"Mythril analysis failed: {str(e)}"}

def generate_report(slither_results, mythril_results):
    """Generate a security report from both analysis tools."""
    report = {
        "slither": slither_results,
        "mythril": mythril_results
    }
    with open("security_report.json", "w") as file:
        json.dump(report, file, indent=4)
    print("Security report generated: security_report.json")

def open_report():
    """Open the generated security report file."""
    try:
        if platform.system() == "Darwin":  
            subprocess.run(["open", "security_report.json"])
        elif platform.system() == "Windows":
            subprocess.run(["start", "security_report.json"], shell=True)
        else:  # Linux
            subprocess.run(["xdg-open", "security_report.json"])
    except FileNotFoundError:
        print("Security report file not found.")

def main():
    # Example Solidity smart contract code
    contract_code = """
    // SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MultiSigWallet {
    
    event Deposit(address indexed sender, uint amount);
    event TransactionProposed(uint indexed txId, address indexed to, uint value, bytes data);
    event TransactionApproved(address indexed owner, uint indexed txId);
    event TransactionExecuted(uint indexed txId);
    event TransactionRevoked(address indexed owner, uint indexed txId);

    struct Transaction {
        address to;
        uint value;
        bytes data;
        bool executed;
        uint approvalCount;
    }

    address[] public owners;
    mapping(address => bool) public isOwner;
    uint public requiredApprovals;

    Transaction[] public transactions;
    mapping(uint => mapping(address => bool)) public approvals;
    modifier onlyOwner() {
        require(isOwner[msg.sender], "Not an owner");
        _;
    }

    modifier txExists(uint _txId) {
        require(_txId < transactions.length, "Transaction does not exist");
        _;
    }

    modifier notApproved(uint _txId) {
        require(!approvals[_txId][msg.sender], "Already approved");
        _;
    }

    modifier notExecuted(uint _txId) {
        require(!transactions[_txId].executed, "Transaction already executed");
        _;
    }

    constructor(address[] memory _owners, uint _requiredApprovals) {
        require(_owners.length > 0, "Owners required");
        require(_requiredApprovals > 0 && _requiredApprovals <= _owners.length, "Invalid required approvals");

        for (uint i = 0; i < _owners.length; i++) {
            address owner = _owners[i];
            require(owner != address(0), "Invalid owner");
            require(!isOwner[owner], "Owner not unique");

            isOwner[owner] = true;
            owners.push(owner);
        }

        requiredApprovals = _requiredApprovals;
    }

    receive() external payable {
        emit Deposit(msg.sender, msg.value);
    }

    function proposeTransaction(address _to, uint _value, bytes memory _data) external onlyOwner {
        transactions.push(Transaction({
            to: _to,
            value: _value,
            data: _data,
            executed: false,
            approvalCount: 0
        }));

        emit TransactionProposed(transactions.length - 1, _to, _value, _data);
    }

    function approveTransaction(uint _txId) external onlyOwner txExists(_txId) notApproved(_txId) notExecuted(_txId) {
        approvals[_txId][msg.sender] = true;
        transactions[_txId].approvalCount += 1;

        emit TransactionApproved(msg.sender, _txId);
    }

    function executeTransaction(uint _txId) external onlyOwner txExists(_txId) notExecuted(_txId) {
        Transaction storage transaction = transactions[_txId];
        require(transaction.approvalCount >= requiredApprovals, "Not enough approvals");

        transaction.executed = true;

        (bool success, ) = transaction.to.call{value: transaction.value}(transaction.data);
        require(success, "Transaction failed");

        emit TransactionExecuted(_txId);
    }

    function revokeApproval(uint _txId) external onlyOwner txExists(_txId) notExecuted(_txId) {
        require(approvals[_txId][msg.sender], "Transaction not approved");

        approvals[_txId][msg.sender] = false;
        transactions[_txId].approvalCount -= 1;

        emit TransactionRevoked(msg.sender, _txId);
    }

    function getTransactionCount() public view returns (uint) {
        return transactions.length;
    }
}

    """
    
    print("Running Slither...")
    slither_results = run_slither(contract_code)
    
    print("Running Mythril...")
    mythril_results = run_mythril(contract_code)
    
    generate_report(slither_results, mythril_results)
    print("Analysis complete. Check security_report.json for details.")
    
    open_report()

if __name__ == "__main__":
    main()
