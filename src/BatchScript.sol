// SPDX-License-Identifier: MIT
pragma solidity >=0.6.2 <0.9.0;

// 💬 ABOUT
// Gnosis Safe transaction batching script

// 🧩 MODULES
import {Script, console2, StdChains, stdJson, stdMath, StdStorage, stdStorageSafe, VmSafe} from "forge-std/Script.sol";

import {Surl} from "../lib/surl/src/Surl.sol";

// ⭐️ SCRIPT
abstract contract BatchScript is Script {
    using stdJson for string;
    using Surl for *;

    //     "to": "<checksummed address>",
    //     "value": 0, // Value in wei
    //     "data": "<0x prefixed hex string>",
    //     "operation": 0,  // 0 CALL, 1 DELEGATE_CALL
    //     "safeTxGas": 0,  // Max gas to use in the transaction

    // Used by refund mechanism, not needed here
    //     "gasToken": "<checksummed address>", // Token address (hold by the Safe) to be used as a refund to the sender, if `null` is Ether
    //     "baseGas": 0,  // Gast costs not related to the transaction execution (signature check, refund payment...)
    //     "gasPrice": 0,  // Gas price used for the refund calculation
    //     "refundReceiver": "<checksummed address>", //Address of receiver of gas payment (or `null` if tx.origin)

    //     "nonce": 0,  // Nonce of the Safe, transaction cannot be executed until Safe's nonce is not equal to this nonce
    //     "contractTransactionHash": "string",  // Contract transaction hash calculated from all the field
    //     "sender": "<checksummed address>",  // Owner of the Safe proposing the transaction. Must match one of the signatures
    //     "signature": "<0x prefixed hex string>",  // One or more ethereum ECDSA signatures of the `contractTransactionHash` as an hex string

    // Not required
    //     "origin": "string"  // Give more information about the transaction, e.g. "My Custom Safe app"

    // Hash constants
    // Safe version for this script, hashes below depend on this
    string private constant VERSION = "1.3.0";

    // keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");
    bytes32 private constant DOMAIN_SEPARATOR_TYPEHASH =
        0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;

    // keccak256(
    //     "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
    // );
    bytes32 private constant SAFE_TX_TYPEHASH =
        0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;

    // Deterministic deployment address of the Gnosis Safe Multisend contract, configured by chain.
    address private SAFE_MULTISEND_ADDRESS;

    // Chain ID, configured by chain.
    uint256 private chainId;

    // Safe API base URL, configured by chain.
    string private SAFE_API_BASE_URL;
    string private constant SAFE_API_MULTISIG_SEND = "/multisig-transactions/";

    // Wallet information
    bytes32 private walletType;
    uint256 private mnemonicIndex;
    bytes32 private privateKey;

    bytes32 private constant LOCAL = keccak256("local");
    bytes32 private constant LEDGER = keccak256("ledger");

    // Address to send transaction from
    address private safe;

    enum Operation {
        CALL,
        DELEGATECALL
    }

    struct Batch {
        address to;
        uint256 value;
        bytes data;
        Operation operation;
        uint256 safeTxGas;
        uint256 baseGas;
        uint256 gasPrice;
        address gasToken;
        address refundReceiver;
        uint256 nonce;
        bytes32 txHash;
        bytes signature;
    }

    bytes[] public encodedTxns;

    // Modifiers

    modifier isBatch(address safe_) {
        // Set the chain ID
        chainId = getChainID();

        // Set the Safe API base URL and multisend address based on chain
        if (chainId == 1) {
            SAFE_API_BASE_URL = "https://safe-transaction-mainnet.safe.global/api/v1/safes/";
            SAFE_MULTISEND_ADDRESS = 0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761;
        } else if (chainId == 5) {
            SAFE_API_BASE_URL = "https://safe-transaction-goerli.safe.global/api/v1/safes/";
            SAFE_MULTISEND_ADDRESS = 0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761;
        } else if (chainId == 8453) {
            SAFE_API_BASE_URL = "https://safe-transaction-base.safe.global/api/v1/safes/";
            SAFE_MULTISEND_ADDRESS = 0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761;
        } else if (chainId == 42161) {
            SAFE_API_BASE_URL = "https://safe-transaction-arbitrum.safe.global/api/v1/safes/";
            SAFE_MULTISEND_ADDRESS = 0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761;
        } else if (chainId == 43114) {
            SAFE_API_BASE_URL = "https://safe-transaction-avalanche.safe.global/api/v1/safes/";
            SAFE_MULTISEND_ADDRESS = 0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761;
        } else if (chainId == 80084) {
            SAFE_API_BASE_URL = "https://transaction-bartio.safe.berachain.com/api/v1/safes/";
            SAFE_MULTISEND_ADDRESS = 0x94092182D03fE8517A0345c455caA8047f9feb5b;
        } else if (chainId == 80094) {
            SAFE_API_BASE_URL = "https://transaction.bp.w3us.site/";
            SAFE_MULTISEND_ADDRESS = 0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761;
        } else {
            revert("Unsupported chain");
        }

        // Store the provided safe address
        safe = safe_;

        // Load wallet information
        walletType = keccak256(abi.encodePacked(vm.envString("WALLET_TYPE")));
        if (walletType == LOCAL) {
            privateKey = vm.envBytes32("PRIVATE_KEY");
        } else if (walletType == LEDGER) {
            mnemonicIndex = vm.envUint("MNEMONIC_INDEX");
        } else {
            revert("Unsupported wallet type");
        }

        // Run batch
        _;
    }

    function getChainID() public view returns (uint256) {
        uint256 id;
        assembly {
            id := chainid()
        }
        return id;
    }

    // Functions to consume in a script

    // Adds an encoded transaction to the batch.
    // Encodes the transaction as packed bytes of:
    // - `operation` as a `uint8` with `0` for a `call` or `1` for a `delegatecall` (=> 1 byte),
    // - `to` as an `address` (=> 20 bytes),
    // - `value` as in msg.value, sent as a `uint256` (=> 32 bytes),
    // -  length of `data` as a `uint256` (=> 32 bytes),
    // - `data` as `bytes`.
    function addToBatch(
        address to_,
        uint256 value_,
        bytes memory data_
    ) internal returns (bytes memory) {
        // Add transaction to batch array
        encodedTxns.push(abi.encodePacked(Operation.CALL, to_, value_, data_.length, data_));

        // Simulate transaction and get return value
        vm.prank(safe);
        (bool success, bytes memory data) = to_.call{value: value_}(data_);
        if (success) {
            return data;
        } else {
            revert(string(data));
        }
    }

    // Convenience funtion to add an encoded transaction to the batch, but passes
    // 0 as the `value` (equivalent to msg.value) field.
    function addToBatch(address to_, bytes memory data_) internal returns (bytes memory) {
        // Add transaction to batch array
        encodedTxns.push(abi.encodePacked(Operation.CALL, to_, uint256(0), data_.length, data_));

        // Simulate transaction and get return value
        vm.prank(safe);
        (bool success, bytes memory data) = to_.call(data_);
        if (success) {
            return data;
        } else {
            revert(string(data));
        }
    }

    // Simulate then send the batch to the Safe API. If `send_` is `false`, the
    // batch will only be simulated.
    function executeBatch(bool send_) internal {
        Batch memory batch = _createBatch(safe);
        // _simulateBatch(safe, batch);
        if (send_) {
            batch = _signBatch(safe, batch);
            _sendBatch(safe, batch);
        }
    }

    // Private functions

    // Encodes the stored encoded transactions into a single Multisend transaction
    function _createBatch(address safe_) private returns (Batch memory batch) {
        // Set initial batch fields
        batch.to = SAFE_MULTISEND_ADDRESS;
        batch.value = 0;
        batch.operation = Operation.DELEGATECALL;

        // Encode the batch calldata. The list of transactions is tightly packed.
        bytes memory data;
        uint256 len = encodedTxns.length;
        for (uint256 i; i < len; ++i) {
            data = bytes.concat(data, encodedTxns[i]);
        }
        batch.data = abi.encodeWithSignature("multiSend(bytes)", data);

        // Batch gas parameters can all be zero and don't need to be set

        // Get the safe nonce
        batch.nonce = _getNonce(safe_);

        // Get the transaction hash
        batch.txHash = _getTransactionHash(safe_, batch);
    }

    function _signBatch(
        address safe_,
        Batch memory batch_
    ) private returns (Batch memory) {
        // Get the typed data to sign
        string memory typedData = _getTypedData(safe_, batch_);

        vm.writeJson(typedData, "./batch-output.json");

        // Construct the sign command
        string memory commandStart = "cast wallet sign ";
        string memory wallet;
        if (walletType == LOCAL) {
            wallet = string.concat(
                "--private-key ",
                vm.toString(privateKey),
                " "
            );
        } else if (walletType == LEDGER) {
            wallet = string.concat(
                "--ledger --mnemonic-index ",
                vm.toString(mnemonicIndex),
                " "
            );
        } else {
            revert("Unsupported wallet type");
        }
        string memory commandEnd = "--data --from-file ";

        // Sign the typed data from the CLI and get the signature
        string[] memory inputs = new string[](3);
        inputs[0] = "bash";
        inputs[1] = "-c";
        inputs[2] = string.concat(
            commandStart,
            wallet,
            commandEnd,
            "./batch-output.json"
        );
        bytes memory signature = vm.ffi(inputs);

        // Set the signature on the batch
        batch_.signature = signature;

        vm.removeFile("./batch-output.json");

        return batch_;
    }

    function _sendBatch(address safe_, Batch memory batch_) private {
        string memory endpoint = _getSafeAPIEndpoint(safe_);

        // Create json payload for API call to Gnosis transaction service
        string memory placeholder = "";
        placeholder.serialize("safe", safe_);
        placeholder.serialize("to", batch_.to);
        placeholder.serialize("value", batch_.value);
        placeholder.serialize("data", batch_.data);
        placeholder.serialize("operation", uint256(batch_.operation));
        placeholder.serialize("safeTxGas", batch_.safeTxGas);
        placeholder.serialize("baseGas", batch_.baseGas);
        placeholder.serialize("gasPrice", batch_.gasPrice);
        placeholder.serialize("nonce", batch_.nonce);
        placeholder.serialize("gasToken", address(0));
        placeholder.serialize("refundReceiver", address(0));
        placeholder.serialize("contractTransactionHash", batch_.txHash);
        placeholder.serialize("signature", batch_.signature);
        string memory payload = placeholder.serialize("sender", msg.sender);

        vm.writeJson(payload,"./temp-payload.json");

        // Send batch
        (uint256 status, bytes memory data) = endpoint.post(
            _getHeaders(),
            "@temp-payload.json"
        );

        if (status == 201) {
            console2.log("Batch sent successfully");
        } else {
            console2.log(string(data));
            revert("Send batch failed!");
        }

        vm.removeFile("./temp-payload.json");
    }

    // Computes the EIP712 hash of a Safe transaction.
    // Look at https://github.com/safe-global/safe-eth-py/blob/174053920e0717cc9924405e524012c5f953cd8f/gnosis/safe/safe_tx.py#L186
    // and https://github.com/safe-global/safe-eth-py/blob/master/gnosis/eth/eip712/__init__.py
    function _getTransactionHash(
        address safe_,
        Batch memory batch_
    ) private view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    hex"1901",
                    keccak256(
                        abi.encode(DOMAIN_SEPARATOR_TYPEHASH, chainId, safe_)
                    ),
                    keccak256(
                        abi.encode(
                            SAFE_TX_TYPEHASH,
                            batch_.to,
                            batch_.value,
                            keccak256(batch_.data),
                            batch_.operation,
                            batch_.safeTxGas,
                            batch_.baseGas,
                            batch_.gasPrice,
                            address(0),
                            address(0),
                            batch_.nonce
                        )
                    )
                )
            );
    }

    function _getTypedData(
        address safe_,
        Batch memory batch_
    ) private returns (string memory) {
        // Create EIP712 structured data for the batch transaction to sign externally via cast

        // EIP712Domain Field Types
        string[] memory domainTypes = new string[](2);
        string memory t = "domainType0";
        vm.serializeString(t, "name", "verifyingContract");
        domainTypes[0] = vm.serializeString(t, "type", "address");
        t = "domainType1";
        vm.serializeString(t, "name", "chainId");
        domainTypes[1] = vm.serializeString(t, "type", "uint256");

        // SafeTx Field Types
        string[] memory txnTypes = new string[](10);
        t = "txnType0";
        vm.serializeString(t, "name", "to");
        txnTypes[0] = vm.serializeString(t, "type", "address");
        t = "txnType1";
        vm.serializeString(t, "name", "value");
        txnTypes[1] = vm.serializeString(t, "type", "uint256");
        t = "txnType2";
        vm.serializeString(t, "name", "data");
        txnTypes[2] = vm.serializeString(t, "type", "bytes");
        t = "txnType3";
        vm.serializeString(t, "name", "operation");
        txnTypes[3] = vm.serializeString(t, "type", "uint8");
        t = "txnType4";
        vm.serializeString(t, "name", "safeTxGas");
        txnTypes[4] = vm.serializeString(t, "type", "uint256");
        t = "txnType5";
        vm.serializeString(t, "name", "baseGas");
        txnTypes[5] = vm.serializeString(t, "type", "uint256");
        t = "txnType6";
        vm.serializeString(t, "name", "gasPrice");
        txnTypes[6] = vm.serializeString(t, "type", "uint256");
        t = "txnType7";
        vm.serializeString(t, "name", "gasToken");
        txnTypes[7] = vm.serializeString(t, "type", "address");
        t = "txnType8";
        vm.serializeString(t, "name", "refundReceiver");
        txnTypes[8] = vm.serializeString(t, "type", "address");
        t = "txnType9";
        vm.serializeString(t, "name", "nonce");
        txnTypes[9] = vm.serializeString(t, "type", "uint256");

        // Create the top level types object
        t = "topLevelTypes";
        t.serialize("EIP712Domain", domainTypes);
        string memory types = t.serialize("SafeTx", txnTypes);

        // Create the message object
        string memory m = "message";
        m.serialize("to", batch_.to);
        m.serialize("value", batch_.value);
        m.serialize("data", batch_.data);
        m.serialize("operation", uint256(batch_.operation));
        m.serialize("safeTxGas", batch_.safeTxGas);
        m.serialize("baseGas", batch_.baseGas);
        m.serialize("gasPrice", batch_.gasPrice);
        m.serialize("gasToken", address(0));
        m.serialize("refundReceiver", address(0));
        string memory message = m.serialize("nonce", batch_.nonce);

        // Create the domain object
        string memory d = "domain";
        d.serialize("verifyingContract", safe_);
        string memory domain = d.serialize("chainId", chainId);

        // Create the payload object
        string memory p = "payload";
        p.serialize("types", types);
        vm.serializeString(p, "primaryType", "SafeTx");
        p.serialize("domain", domain);
        string memory payload = p.serialize("message", message);

        payload = _stripSlashQuotes(payload);

        return payload;
    }

    // function _stripSlashQuotes(
    //     string memory str_
    // ) private returns (string memory) {
    //     // Remove slash quotes from string
    //     string memory command = string.concat(
    //         "sed 's/",
    //         '\\\\"/"',
    //         "/g; s/",
    //         '\\"',
    //         "\\[/\\[/g; s/",
    //         '\\]\\"',
    //         "/\\]/g; s/",
    //         '\\"',
    //         "{/{/g; s/",
    //         '}\\"',
    //         "/}/g;' <<< "
    //     );

    //     string[] memory inputs = new string[](3);
    //     inputs[0] = "bash";
    //     inputs[1] = "-c";
    //     inputs[2] = string.concat(command, "'", str_, "'");
    //     bytes memory res = vm.ffi(inputs);

    //     return string(res);
    // }

    function _stripSlashQuotes(
        string memory str_
    ) private returns (string memory) {
        // Write the input string to a temporary file
        string memory tempFile = "./temp_input.txt";
        // string[] memory staging = new string[](3);
        // staging[0]= "bash";
        // staging[1] = "-c";
        // staging[2] = string.concat("echo -n ", str_, " > ", tempFile);
        // vm.ffi(staging);
        vm.writeFile(tempFile, str_);

        // Construct the sed command using the temporary file
        string memory command = string.concat(
            "sed 's/",
            '\\\\"/"',
            "/g; s/",
            '\\"',
            "\\[/\\[/g; s/",
            '\\]\\"',
            "/\\]/g; s/",
            '\\"',
            "{/{/g; s/",
            '}\\"',
            "/}/g;' ",
            tempFile
        );

        // Execute the sed command and read the result
        string[] memory inputs = new string[](3);
        inputs[0] = "bash";
        inputs[1] = "-c";
        inputs[2] = command;
        bytes memory res = vm.ffi(inputs);

        vm.removeFile(tempFile);

        return string(res);
    }

    function _getNonce(address safe_) private returns (uint256) {
        string memory endpoint = string.concat(
            _getSafeAPIEndpoint(safe_),
            "?limit=1"
        );
        // (uint256 status, bytes memory data) = endpoint.get();
        (uint256 status, string memory dataFile) = curl(endpoint, "", "GET");
        if (status == 200) {
            
            string memory json = vm.readFile(dataFile);
            // Check if results array is empty
            uint256 resultsCount = json.readUint(".count");
            if (resultsCount == 0) {
                return 0;
            }
            uint256 lastNonce = json.readUint(".results[0].nonce");
            return lastNonce + 1;
        } else {
            revert("Get nonce failed!");
        }
    }

    function curl(string memory self, string memory body, string memory method)
        internal
        returns (uint256 status, string memory data)
    {
        string memory scriptStart = 'response=$(curl -s -w "\\n%{http_code}" ';
        string memory scriptEnd = '); status=$(tail -n1 <<< "$response"); data=$(sed "$ d" <<< "$response");data=$(echo "$data" | tr -d "\\n"); echo "$data" > tmp-curl-response.json; cast abi-encode "response(uint256,string)" "$status" "tmp-curl-response.json";';

        string memory curlParams = "";

        // for (uint256 i = 0; i < headers.length; i++) {
        //     curlParams = string.concat(curlParams, '-H "', headers[i], '" ');
        // }

        curlParams = string.concat(curlParams, " -X ", method, " ");

        if (bytes(body).length > 0) {
            curlParams = string.concat(curlParams, ' -d \'', body, '\' ');
        }

        string memory quotedURL = string.concat('"', self, '"');

        string[] memory inputs = new string[](3);
        inputs[0] = "bash";
        inputs[1] = "-c";
        inputs[2] = string.concat(scriptStart, curlParams, quotedURL, scriptEnd, "");
        bytes memory res = vm.ffi(inputs);

        (status, data) = abi.decode(res, (uint256, string));
    }

    function _getSafeAPIEndpoint(
        address safe_
    ) private view returns (string memory) {
        return
            string.concat(
                SAFE_API_BASE_URL,
                vm.toString(safe_),
                SAFE_API_MULTISIG_SEND
            );
    }

    function _getHeaders() private pure returns (string[] memory) {
        string[] memory headers = new string[](1);
        headers[0] = "Content-Type: application/json";
        return headers;
    }
}
