#include <iostream>
#include <vector>
#include <map>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <functional>
#include <fstream>
#include <cstdint>
#include <cstring>
#include <array>

using namespace std;

// ================= REAL SHA256 IMPLEMENTATION =================
// Based on the FIPS 180-4 standard. Public domain / CC0.
class SHA256 {
public:
    SHA256() { reset(); }

    void update(const uint8_t* data, size_t length) {
        for (size_t i = 0; i < length; ++i) {
            buffer_[data_len_] = data[i];
            data_len_++;
            if (data_len_ == 64) {
                process_block(buffer_.data());
                total_len_ += 512;
                data_len_ = 0;
            }
        }
    }

    void update(const string& data) {
        update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    }

    array<uint8_t, 32> finalize() {
        // Padding: append the bit '1'
        uint64_t bit_len = total_len_ + data_len_ * 8;
        buffer_[data_len_] = 0x80;
        data_len_++;

        // If no room for length (8 bytes), pad this block and process
        if (data_len_ > 56) {
            while (data_len_ < 64) buffer_[data_len_++] = 0;
            process_block(buffer_.data());
            data_len_ = 0;
        }
        // Pad with zeros until 56 bytes
        while (data_len_ < 56) buffer_[data_len_++] = 0;

        // Append the 64‑bit length (big-endian)
        buffer_[56] = static_cast<uint8_t>(bit_len >> 56);
        buffer_[57] = static_cast<uint8_t>(bit_len >> 48);
        buffer_[58] = static_cast<uint8_t>(bit_len >> 40);
        buffer_[59] = static_cast<uint8_t>(bit_len >> 32);
        buffer_[60] = static_cast<uint8_t>(bit_len >> 24);
        buffer_[61] = static_cast<uint8_t>(bit_len >> 16);
        buffer_[62] = static_cast<uint8_t>(bit_len >> 8);
        buffer_[63] = static_cast<uint8_t>(bit_len);

        process_block(buffer_.data());

        // Produce final hash (big-endian bytes)
        array<uint8_t, 32> hash;
        for (int i = 0; i < 8; ++i) {
            hash[i*4]   = (h_[i] >> 24) & 0xff;
            hash[i*4+1] = (h_[i] >> 16) & 0xff;
            hash[i*4+2] = (h_[i] >> 8) & 0xff;
            hash[i*4+3] = h_[i] & 0xff;
        }
        reset();
        return hash;
    }

    string finalize_hex() {
        auto hash = finalize();
        stringstream ss;
        for (uint8_t byte : hash)
            ss << hex << setw(2) << setfill('0') << (int)byte;
        return ss.str();
    }

private:
    void reset() {
        h_[0] = 0x6a09e667;
        h_[1] = 0xbb67ae85;
        h_[2] = 0x3c6ef372;
        h_[3] = 0xa54ff53a;
        h_[4] = 0x510e527f;
        h_[5] = 0x9b05688c;
        h_[6] = 0x1f83d9ab;
        h_[7] = 0x5be0cd19;
        data_len_ = 0;
        total_len_ = 0;
    }

    void process_block(const uint8_t* block) {
        static const uint32_t K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (block[i*4] << 24) | (block[i*4+1] << 16) |
                   (block[i*4+2] << 8) | block[i*4+3];
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = (w[i-15] >> 7) | (w[i-15] << 25);
            uint32_t s1 = (w[i-2] >> 17) | (w[i-2] << 15);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }

        uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
        uint32_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = (e >> 6) | (e << 26);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + K[i] + w[i];
            uint32_t S0 = (a >> 2) | (a << 30);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h_[0] += a;
        h_[1] += b;
        h_[2] += c;
        h_[3] += d;
        h_[4] += e;
        h_[5] += f;
        h_[6] += g;
        h_[7] += h;

        total_len_ += 512;
    }

    uint32_t h_[8];
    array<uint8_t, 64> buffer_;  // changed to std::array
    size_t data_len_;            // bytes in buffer
    uint64_t total_len_;         // bits processed (now uint64_t)
};

// Convenience wrapper that returns hex string
string sha256(const string& input) {
    SHA256 sha;
    sha.update(input);
    return sha.finalize_hex();
}

// ================= DATA STRUCTURES =================

struct Transaction {
    string from;
    string to;
    int amount;
    string signature;
};

struct Block {
    int index;
    time_t timestamp;
    string prevHash;
    string hash;
    long nonce;
    string merkleRoot;
};

// ================= BLOCKCHAIN CLASS =================

class Blockchain {
public:
    vector<Block> chain;
    const string DATA_FILE = "blockchain_data.txt";

    Blockchain() {
        if (!loadFromFile()) {
            createGenesis();
        }
    }

    void createGenesis() {
        Block g;
        g.index = 0;
        g.timestamp = time(nullptr);
        g.prevHash = "0";
        g.hash = sha256("genesis");
        g.nonce = 0;
        chain.push_back(g);
        saveToFile();
    }

    void mineBlock() {
        Block b;
        b.index = chain.size();
        b.timestamp = time(nullptr);
        b.prevHash = chain.back().hash;

        // Simplified Merkle Root (now using the proper SHA256)
        b.merkleRoot = sha256("tx_data_" + to_string(b.timestamp));

        long nonce = 0;
        while (true) {
            string data = b.prevHash + to_string(b.timestamp) + to_string(nonce) + b.merkleRoot;
            string h = sha256(data);
            if (h.substr(0, 4) == "0000") {
                b.hash = h;
                b.nonce = nonce;
                break;
            }
            nonce++;
        }
        chain.push_back(b);
        saveToFile();
    }

    void saveToFile() {
        ofstream file(DATA_FILE);
        for (const auto& b : chain) {
            file << b.index << "|" << b.hash << "|" << b.prevHash << "|" << b.timestamp << "\n";
        }
        file.close();
    }

    bool loadFromFile() {
        ifstream file(DATA_FILE);
        if (!file.is_open()) return false;

        chain.clear();
        string line;
        while (getline(file, line)) {
            stringstream ss(line);
            string segment;
            Block b;
            int i = 0;
            while (getline(ss, segment, '|')) {
                if (i == 0) b.index = stoi(segment);
                else if (i == 1) b.hash = segment;
                else if (i == 2) b.prevHash = segment;
                else if (i == 3) b.timestamp = stoll(segment);
                i++;
            }
            chain.push_back(b);
        }
        file.close();
        return !chain.empty();
    }
};

// ================= MAIN EXECUTION =================

int main() {
    Blockchain bc;

    // Every time this EXE runs, it mines a new block
    bc.mineBlock();

    // Output JSON for Node.js to read
    cout << "{"
         << "\"status\": \"active\","
         << "\"blockCount\": " << bc.chain.size() << ","
         << "\"latestBlock\": {"
         << "\"index\": " << bc.chain.back().index << ","
         << "\"hash\": \"" << bc.chain.back().hash << "\","
         << "\"prevHash\": \"" << bc.chain.back().prevHash << "\","
         << "\"nonce\": " << bc.chain.back().nonce << ","
         << "\"merkleRoot\": \"" << bc.chain.back().merkleRoot << "\""
         << "}"
         << "}";

    return 0;
}