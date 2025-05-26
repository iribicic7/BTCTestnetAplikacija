#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <curl/curl.h>
#include "json.hpp"
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

using json = nlohmann::json;

// --- Pomoćne fje ---

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    if (hex.empty()) {
        throw std::runtime_error("Empty hex string");
    }
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("Hex string has odd length");
    }

    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.size(); i += 2) {
        std::string byteStr = hex.substr(i, 2);
        try {
            uint8_t byte = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
            bytes.push_back(byte);
        } catch (...) {
            throw std::runtime_error("Invalid hex character in: " + byteStr);
        }
    }
    return bytes;
}

std::string bytesToHex(const std::vector<uint8_t>& data) {
    std::string hex;
    const char* digits = "0123456789abcdef";
    for (auto b : data) {
        hex += digits[b >> 4];
        hex += digits[b & 0xF];
    }
    return hex;
}

void writeUint32LE(std::vector<uint8_t>& buf, uint32_t value) {
    buf.push_back(value & 0xFF);
    buf.push_back((value >> 8) & 0xFF);
    buf.push_back((value >> 16) & 0xFF);
    buf.push_back((value >> 24) & 0xFF);
}

void writeUint64LE(std::vector<uint8_t>& buf, uint64_t value) {
    for (int i = 0; i < 8; i++) {
        buf.push_back(value & 0xFF);
        value >>= 8;
    }
}

void writeVarInt(std::vector<uint8_t>& buf, uint64_t v) {
    if (v < 0xFD) {
        buf.push_back(v);
    } else if (v <= 0xFFFF) {
        buf.push_back(0xFD);
        buf.push_back(v & 0xFF);
        buf.push_back((v >> 8) & 0xFF);
    } else if (v <= 0xFFFFFFFF) {
        buf.push_back(0xFE);
        writeUint32LE(buf, (uint32_t)v);
    } else {
        buf.push_back(0xFF);
        writeUint64LE(buf, v);
    }
}

std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(32);
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.data(), data.size());
    SHA256_Final(hash.data(), &ctx);
    return hash;
}

std::vector<uint8_t> ripemd160(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(20);
    RIPEMD160_CTX ctx;
    RIPEMD160_Init(&ctx);
    RIPEMD160_Update(&ctx, data.data(), data.size());
    RIPEMD160_Final(hash.data(), &ctx);
    return hash;
}

std::vector<uint8_t> hash160(const std::vector<uint8_t>& data) {
    return ripemd160(sha256(data));
}

std::vector<uint8_t> reverseBytes(const std::vector<uint8_t>& in) {
    std::vector<uint8_t> out = in;
    std::reverse(out.begin(), out.end());
    return out;
}

// --- HTTP GET ---

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

std::string httpGet(const std::string& url) {
    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("CURL init failed");

    std::string readBuffer;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L); // Increased timeout
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        throw std::runtime_error("CURL failed: " + std::string(curl_easy_strerror(res)));
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (http_code != 200) {
        throw std::runtime_error("HTTP error " + std::to_string(http_code) + ": " + readBuffer);
    }

    return readBuffer;
}

std::string httpPost(const std::string& url, const std::string& postData) {
    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("curl init failed");
    
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    std::string readBuffer;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        throw std::runtime_error("curl failed: " + std::string(curl_easy_strerror(res)));
    }
    
    if (http_code != 200 && http_code != 201) {
        throw std::runtime_error("HTTP error: " + std::to_string(http_code) + " - Response: " + readBuffer);
    }
    
    return readBuffer;
}

// --- Uzimanje UTXO-a sa mempool.space ---
std::vector<json> fetchUTXOs(const std::string& address) {
    std::string url = "https://mempool.space/testnet/api/address/" + address + "/utxo";
    std::string res = httpGet(url);
    std::cout << "Raw API response: " << res << std::endl;
    
    try {
        json j = json::parse(res);
        // Fetch each UTXO's transaction to get the scriptPubKey
        for (auto& utxo : j) {
            std::string txUrl = "https://mempool.space/testnet/api/tx/" + utxo["txid"].get<std::string>();
            std::string txRes = httpGet(txUrl);
            json txData = json::parse(txRes);
            int vout = utxo["vout"].get<int>();
            utxo["scriptPubKey"] = txData["vout"][vout]["scriptpubkey"];
        }
        return j.get<std::vector<json>>();
    } catch (const json::parse_error& e) {
        throw std::runtime_error("Failed to parse UTXO response: " + std::string(e.what()));
    }
}

// --- Bech32 decode ---
const std::string CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
int CHARSET_REV[128];

void initCharsetRev() {
    std::fill_n(CHARSET_REV, 128, -1);
    for (size_t i = 0; i < CHARSET.size(); i++) CHARSET_REV[(int)CHARSET[i]] = i;
}

uint32_t bech32Polymod(const std::vector<uint8_t>& values) {
    const uint32_t GEN[] = {0x3b6a57b2UL, 0x26508e6dUL, 0x1ea119faUL, 0x3d4233ddUL, 0x2a1462b3UL};
    uint32_t chk = 1;
    for (uint8_t v : values) {
        uint8_t top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (int i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GEN[i];
    }
    return chk;
}

std::vector<uint8_t> bech32HrpExpand(const std::string& hrp) {
    std::vector<uint8_t> ret;
    for (char c : hrp) ret.push_back((uint8_t)(c >> 5));
    ret.push_back(0);
    for (char c : hrp) ret.push_back((uint8_t)(c & 31));
    return ret;
}

bool bech32VerifyChecksum(const std::string& hrp, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> values = bech32HrpExpand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    return bech32Polymod(values) == 1;
}

bool bech32Decode(const std::string& addr, std::string& hrp, std::vector<uint8_t>& data) {
    if (addr.size() < 8) return false;
    size_t pos = addr.find_last_of('1');
    if (pos == std::string::npos || pos < 1 || pos + 7 > addr.size()) return false;
    hrp = addr.substr(0, pos);
    std::string dataPart = addr.substr(pos + 1);
    data.clear();
    initCharsetRev();
    for (char c : dataPart) {
        if (c < 33 || c > 126) return false;
        int val = CHARSET_REV[(int)c];
        if (val == -1) return false;
        data.push_back(val);
    }
    return bech32VerifyChecksum(hrp, data);
}

bool convertBits(const std::vector<uint8_t>& in, int fromBits, int toBits, bool pad, std::vector<uint8_t>& out) {
    int acc = 0;
    int bits = 0;
    const int maxv = (1 << toBits) - 1;
    for (auto value : in) {
        if (value < 0 || (value >> fromBits) != 0) return false;
        acc = (acc << fromBits) | value;
        bits += fromBits;
        while (bits >= toBits) {
            bits -= toBits;
            out.push_back((acc >> bits) & maxv);
        }
    }
    if (pad) {
        if (bits > 0) out.push_back((acc << (toBits - bits)) & maxv);
    } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv)) {
        return false;
    }
    return true;
}

std::vector<uint8_t> buildP2WPKHScriptPubKey(const std::vector<uint8_t>& pubkeyHash) {
    std::vector<uint8_t> spk;
    spk.push_back(0x00);      // verzija 0
    spk.push_back(0x14);      // guranje 20 bajtova
    spk.insert(spk.end(), pubkeyHash.begin(), pubkeyHash.end());
    return spk;
}

std::vector<uint8_t> buildP2WPKHScriptCode(const std::vector<uint8_t>& pubkeyHash) {
    std::vector<uint8_t> scriptCode;
    scriptCode.push_back(0x76); // OP_DUP
    scriptCode.push_back(0xa9); // OP_HASH160
    scriptCode.push_back(0x14); // guranje 20 bajtova
    scriptCode.insert(scriptCode.end(), pubkeyHash.begin(), pubkeyHash.end());
    scriptCode.push_back(0x88); // OP_EQUALVERIFY
    scriptCode.push_back(0xac); // OP_CHECKSIG
    return scriptCode;
}

void serializeOutpoint(std::vector<uint8_t>& buf, const std::vector<uint8_t>& txid, uint32_t vout) {
    auto txid_le = reverseBytes(txid);
    buf.insert(buf.end(), txid_le.begin(), txid_le.end());
    writeUint32LE(buf, vout);
}

void serializeScript(std::vector<uint8_t>& buf, const std::vector<uint8_t>& script) {
    writeVarInt(buf, script.size());
    buf.insert(buf.end(), script.begin(), script.end());
}

void serializeTxIn(std::vector<uint8_t>& buf,
                 const std::vector<uint8_t>& txid,
                 uint32_t vout,
                 const std::vector<uint8_t>& scriptSig,
                 uint32_t sequence) {
    serializeOutpoint(buf, txid, vout);
    serializeScript(buf, scriptSig);
    writeUint32LE(buf, sequence);
}

void serializeTxOut(std::vector<uint8_t>& buf,
                  uint64_t value,
                  const std::vector<uint8_t>& scriptPubKey) {
    writeUint64LE(buf, value);
    serializeScript(buf, scriptPubKey);
}

std::vector<uint8_t> hashPrevouts(const std::vector<std::vector<uint8_t>>& txids, const std::vector<uint32_t>& vouts) {
    std::vector<uint8_t> buf;
    for (size_t i = 0; i < txids.size(); i++) {
        auto txid_le = reverseBytes(txids[i]);
        buf.insert(buf.end(), txid_le.begin(), txid_le.end());
        writeUint32LE(buf, vouts[i]);
    }
    return sha256(sha256(buf));
}

std::vector<uint8_t> hashSequence(const std::vector<uint32_t>& sequences) {
    std::vector<uint8_t> buf;
    for (auto seq : sequences) writeUint32LE(buf, seq);
    return sha256(sha256(buf));
}

std::vector<uint8_t> hashOutputs(const std::vector<uint64_t>& values, const std::vector<std::vector<uint8_t>>& scriptPubKeys) {
    std::vector<uint8_t> buf;
    for (size_t i = 0; i < values.size(); i++) {
        writeUint64LE(buf, values[i]);
        serializeScript(buf, scriptPubKeys[i]);
    }
    return sha256(sha256(buf));
}

std::vector<uint8_t> createSegwitSighash(
    const std::vector<uint8_t>& txid,
    uint32_t vout,
    const std::vector<uint8_t>& scriptCode,
    uint64_t value,
    uint32_t sequence,
    uint32_t nVersion,
    const std::vector<std::vector<uint8_t>>& prevoutsTxid,
    const std::vector<uint32_t>& prevoutsVout,
    const std::vector<uint32_t>& sequences,
    const std::vector<uint64_t>& outputValues,
    const std::vector<std::vector<uint8_t>>& outputScripts,
    uint32_t inputIndex
) {
    std::vector<uint8_t> buf;
    writeUint32LE(buf, nVersion);

    auto hashPrevouts_ = hashPrevouts(prevoutsTxid, prevoutsVout);
    buf.insert(buf.end(), hashPrevouts_.begin(), hashPrevouts_.end());

    auto hashSequence_ = hashSequence(sequences);
    buf.insert(buf.end(), hashSequence_.begin(), hashSequence_.end());

    auto txid_le = reverseBytes(txid);
    buf.insert(buf.end(), txid_le.begin(), txid_le.end());
    writeUint32LE(buf, vout);

    serializeScript(buf, scriptCode);

    writeUint64LE(buf, value);
    writeUint32LE(buf, sequence);

    auto hashOutputs_ = hashOutputs(outputValues, outputScripts);
    buf.insert(buf.end(), hashOutputs_.begin(), hashOutputs_.end());

    writeUint32LE(buf, 0); // locktime
    writeUint32LE(buf, 0x00000001); // SIGHASH_ALL

    return sha256(sha256(buf));
}

secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

std::vector<uint8_t> signSegwitInput(const std::vector<uint8_t>& sighash32, const std::vector<uint8_t>& privkey) {
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(ctx, &sig, sighash32.data(), privkey.data(), nullptr, nullptr)) {
        throw std::runtime_error("secp256k1 sign failed");
    }
    unsigned char der[72];
    size_t derLen = sizeof(der);
    secp256k1_ecdsa_signature_serialize_der(ctx, der, &derLen, &sig);

    std::vector<uint8_t> signature(der, der + derLen);
    signature.push_back(0x01); // SIGHASH_ALL
    return signature;
}

std::vector<uint8_t> buildWitness(const std::vector<uint8_t>& signature, const std::vector<uint8_t>& pubkey) {
    std::vector<uint8_t> witness;
    
    // Broj witness elemenata - 2 za P2WPKH
    writeVarInt(witness, 2);
    
    // Potpis sa prefixom duljine
    writeVarInt(witness, signature.size());
    witness.insert(witness.end(), signature.begin(), signature.end());
    
    // Javni ključ sa prefixom duljine
    writeVarInt(witness, pubkey.size());
    witness.insert(witness.end(), pubkey.begin(), pubkey.end());
    
    return witness;
}

void serializeWitness(std::vector<uint8_t>& buf, const std::vector<std::vector<uint8_t>>& witnesses) {
    for (const auto& wit : witnesses) {
        buf.insert(buf.end(), wit.begin(), wit.end());
    }
}

std::vector<uint8_t> decodeWIF(const std::string& wif) {
    const std::string base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::vector<uint8_t> bytes;
    int zeroes = 0;
    int index = 0;

    for (char c : wif) {
        auto pos = base58_chars.find(c);
        if (pos == std::string::npos) {
            throw std::runtime_error("Invalid character in WIF");
        }
        
        for (int i = bytes.size() - 1; i >= 0; i--) {
            int val = bytes[i] * 58 + pos;
            bytes[i] = val % 256;
            pos = val / 256;
        }
        
        while (pos > 0) {
            bytes.insert(bytes.begin(), pos % 256);
            pos /= 256;
        }
    }

    if (bytes.size() != 38 || bytes[0] != 0xEF) { // 0xEF je testnet prefix
        throw std::runtime_error("Invalid WIF length or version");
    }
    
    std::vector<uint8_t> checksum(bytes.end() - 4, bytes.end());
    std::vector<uint8_t> data(bytes.begin(), bytes.end() - 4);
    auto hash = sha256(sha256(data));
    if (!std::equal(checksum.begin(), checksum.end(), hash.begin())) {
        throw std::runtime_error("Invalid WIF checksum");
    }
    
    return std::vector<uint8_t>(bytes.begin() + 1, bytes.begin() + 33);
}

int main() {
    try {
        // Po potrebi promijeni adresu i tajni ključ, trenutno se šalje na istu adresu balance - 1000 satoshi kao fee
        const std::string myAddress = "tb1qskck6r694ya4s4n64ew9mfw5j2ufxmrr4xzx2z";
        const std::string privKeyWIF = "cQMNsi9P17CdzswuH9AoDMzsDAZDjo5tREhu1NLYAhppXMrLosUx";
        auto privkey = decodeWIF(privKeyWIF);
        const std::string destAddress = "tb1qskck6r694ya4s4n64ew9mfw5j2ufxmrr4xzx2z";
        const uint64_t feeSat = 1000; // fee u satoshijima

        std::cout << "Fetching UTXOs for address: " << myAddress << std::endl;
        auto utxos = fetchUTXOs(myAddress);
        if (utxos.empty()) {
            std::cerr << "No UTXOs found for address " << myAddress << std::endl;
            return 1;
        }
        std::cout << "Found " << utxos.size() << " UTXOs" << std::endl;

        std::string txUrl = "https://mempool.space/testnet/api/tx/" + utxos[0]["txid"].get<std::string>();
        std::string txData = httpGet(txUrl);
        json txJson = json::parse(txData);
        std::string actualScriptPubKey = txJson["vout"][utxos[0]["vout"].get<int>()]["scriptpubkey"].get<std::string>();
        std::cout << "Actual scriptPubKey: " << actualScriptPubKey << std::endl;

        std::string hrp;
        std::vector<uint8_t> data;

        if (!bech32Decode(myAddress, hrp, data)) {
            throw std::runtime_error("Invalid bech32 source address");
        }
        std::vector<uint8_t> witProgSrc;
        if (!convertBits(std::vector<uint8_t>(data.begin() + 1, data.end() - 6), 5, 8, false, witProgSrc)) {
            throw std::runtime_error("Invalid witness program source");
        }

        if (!bech32Decode(destAddress, hrp, data)) {
            throw std::runtime_error("Invalid bech32 destination address");
        }
        std::vector<uint8_t> witProgDest;
        if (!convertBits(std::vector<uint8_t>(data.begin() + 1, data.end() - 6), 5, 8, false, witProgDest)) {
            throw std::runtime_error("Invalid witness program destination");
        }

        if (privkey.size() != 32) throw std::runtime_error("Invalid privkey size");

        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privkey.data())) {
            throw std::runtime_error("Failed to create pubkey");
        }

        unsigned char pubkeySer[33];
        size_t pubkeyLen = 33;
        secp256k1_ec_pubkey_serialize(ctx, pubkeySer, &pubkeyLen, &pubkey, SECP256K1_EC_COMPRESSED);
        std::vector<uint8_t> pubkeyVec(pubkeySer, pubkeySer + pubkeyLen);

        auto pubkeyHash = hash160(pubkeyVec);
        if (pubkeyHash != witProgSrc) {
            std::cerr << "FATAL: Pubkey hash mismatch!\n";
            std::cerr << "Computed: " << bytesToHex(pubkeyHash) << "\n";
            std::cerr << "Expected: " << bytesToHex(witProgSrc) << "\n";
            throw std::runtime_error("Pubkey does not match address");
        }

        uint64_t totalInputValue = 0;
        for (auto& utxo : utxos) totalInputValue += utxo["value"].get<uint64_t>();
        std::cout << "Total input value: " << totalInputValue << " satoshis" << std::endl;

        if (totalInputValue < feeSat) {
            throw std::runtime_error("Input value less than fee");
        }

        uint64_t sendValue = totalInputValue - feeSat;
        std::cout << "Sending " << sendValue << " satoshis (fee: " << feeSat << " satoshis)" << std::endl;

        std::vector<std::vector<uint8_t>> prevoutsTxid;
        std::vector<uint32_t> prevoutsVout;
        std::vector<uint32_t> sequences(utxos.size(), 0xFFFFFFFF);
        std::vector<uint64_t> outputValues{sendValue};
        std::vector<std::vector<uint8_t>> outputScripts;

        outputScripts.push_back(buildP2WPKHScriptPubKey(witProgDest));

        std::vector<uint8_t> tx;
        writeUint32LE(tx, 2);

        tx.push_back(0x00);
        tx.push_back(0x01);

        writeVarInt(tx, utxos.size());

        for (auto& utxo : utxos) {
            auto txid = hexToBytes(utxo["txid"].get<std::string>());
            uint32_t vout = utxo["vout"].get<uint32_t>();
            serializeTxIn(tx, txid, vout, {}, 0xFFFFFFFF);
            prevoutsTxid.push_back(txid);
            prevoutsVout.push_back(vout);
        }

        writeVarInt(tx, 1);
        serializeTxOut(tx, sendValue, outputScripts[0]);

        std::vector<std::vector<uint8_t>> witnesses;

        for (size_t i = 0; i < utxos.size(); i++) {
            auto scriptPubKeyHex = utxos[i]["scriptPubKey"].get<std::string>();
            std::vector<uint8_t> scriptCode = {
                0x76, 0xa9, 0x14, // OP_DUP OP_HASH160 PUSH20
            };
            scriptCode.insert(scriptCode.end(), witProgSrc.begin(), witProgSrc.end());
            scriptCode.push_back(0x88); // OP_EQUALVERIFY
            scriptCode.push_back(0xac); // OP_CHECKSIG
            uint64_t inputValue = utxos[i]["value"].get<uint64_t>();
            uint32_t sequence = 0xFFFFFFFF;

            auto sighash = createSegwitSighash(
                prevoutsTxid[i], prevoutsVout[i], scriptCode, inputValue, sequence,
                2, prevoutsTxid, prevoutsVout, sequences,
                outputValues, outputScripts, i
            );

            std::cout << "Sighash for input " << i << ": " << bytesToHex(sighash) << std::endl;

            auto sig = signSegwitInput(sighash, privkey);
            witnesses.push_back(buildWitness(sig, pubkeyVec));

            std::cout << "Witness data for input " << i << ":\n";
            std::cout << "Signature: " << bytesToHex(sig) << "\n";
            std::cout << "Pubkey: " << bytesToHex(pubkeyVec) << "\n";
        }

        serializeWitness(tx, witnesses);

        writeUint32LE(tx, 0);

        std::string rawTxHex = bytesToHex(tx);
        std::cout << "\nRaw transaction hex:\n" << rawTxHex << std::endl;

        // --- Broadcastaj na BlockCypher ---
        std::cout << "\nAttempting to broadcast transaction..." << std::endl;
        
        json postData = { {"tx", rawTxHex} };
        std::string postFields = postData.dump();
        
        std::string postUrl = "https://api.blockcypher.com/v1/btc/test3/txs/push";
        
        try {
            std::string response = httpPost(postUrl, postFields);
            std::cout << "\nAPI Response:\n" << response << std::endl;
            
            try {
                auto respJson = json::parse(response);
                if (respJson.contains("tx") && respJson["tx"].contains("hash")) {
                    std::cout << "\nBroadcast success! TXID: " << respJson["tx"]["hash"] << std::endl;
                } else if (respJson.contains("error")) {
                    std::cerr << "\nBroadcast error: " << respJson["error"] << std::endl;
                    return 1;
                } else {
                    std::cerr << "\nUnknown JSON response format" << std::endl;
                    return 1;
                }
            } catch (const json::parse_error& e) {
                std::cerr << "\nFailed to parse JSON response: " << e.what() << std::endl;
                std::cerr << "Raw response: " << response << std::endl;
                return 1;
            }
        } catch (const std::exception& e) {
            std::cerr << "\nFailed to broadcast transaction: " << e.what() << std::endl;
            return 1;
        }

        secp256k1_context_destroy(ctx);
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "\nError: " << e.what() << std::endl;
        return 1;
    }
}