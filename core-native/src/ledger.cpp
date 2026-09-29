#include "ledger.hpp"
extern "C" {
#include "sha256.h"
}
#include <fstream>
#include <sstream>
#include <ctime>
#include <iomanip>
#include <iostream>

static std::string get_current_iso_time() {
    time_t now = time(NULL);
    struct tm *gmt = gmtime(&now);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmt);
    return std::string(buf);
}

std::string ImmutableLedger::calculate_block_hash(const LedgerBlock &blk) {
    std::stringstream ss;
    ss << blk.index << "|"
       << blk.prev_block_hash << "|"
       << blk.timestamp << "|"
       << blk.dispatch_id << "|"
       << blk.sender_id << "|"
       << blk.receiver_id << "|"
       << blk.payload_sha256 << "|"
       << blk.watermark_proof;

    std::string data = ss.str();
    uint8_t hash[32];
    sha256_hash(reinterpret_cast<const uint8_t*>(data.c_str()), data.length(), hash);
    char hex[65];
    sha256_to_hex(hash, hex);
    return std::string(hex);
}

ImmutableLedger::ImmutableLedger(const std::string &ledger_dir) {
    m_storage_path = ledger_dir + "/ledger_blocks.dat";
    m_json_export_path = ledger_dir + "/ledger_audit.json";
    load_chain();
}

void ImmutableLedger::load_chain() {
    m_chain.clear();
    std::ifstream in(m_storage_path.c_str());
    if (!in.is_open()) return;

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        std::stringstream ss(line);
        std::string token;
        std::vector<std::string> parts;
        while (std::getline(ss, token, '\t')) {
            parts.push_back(token);
        }
        if (parts.size() >= 9) {
            LedgerBlock blk;
            blk.index = static_cast<uint32_t>(std::stoul(parts[0]));
            blk.prev_block_hash = parts[1];
            blk.timestamp = parts[2];
            blk.dispatch_id = parts[3];
            blk.sender_id = parts[4];
            blk.receiver_id = parts[5];
            blk.payload_sha256 = parts[6];
            blk.watermark_proof = parts[7];
            blk.block_hash = parts[8];
            m_chain.push_back(blk);
        }
    }
    in.close();
}

void ImmutableLedger::persist_block(const LedgerBlock &blk) {
    std::ofstream out(m_storage_path.c_str(), std::ios::app);
    if (!out.is_open()) return;

    out << blk.index << "\t"
        << blk.prev_block_hash << "\t"
        << blk.timestamp << "\t"
        << blk.dispatch_id << "\t"
        << blk.sender_id << "\t"
        << blk.receiver_id << "\t"
        << blk.payload_sha256 << "\t"
        << blk.watermark_proof << "\t"
        << blk.block_hash << "\n";
    out.flush();
    out.close();

    export_json(m_json_export_path);
}

bool ImmutableLedger::append_block(const std::string &dispatch_id,
                                 const std::string &sender_id,
                                 const std::string &receiver_id,
                                 const std::string &payload_sha256,
                                 const std::string &watermark_proof,
                                 LedgerBlock &out_block) {
    out_block.index = static_cast<uint32_t>(m_chain.size());
    out_block.prev_block_hash = m_chain.empty() ?
        "0000000000000000000000000000000000000000000000000000000000000000" :
        m_chain.back().block_hash;

    out_block.timestamp = get_current_iso_time();
    out_block.dispatch_id = dispatch_id;
    out_block.sender_id = sender_id;
    out_block.receiver_id = receiver_id;
    out_block.payload_sha256 = payload_sha256;
    out_block.watermark_proof = watermark_proof;
    out_block.block_hash = calculate_block_hash(out_block);

    m_chain.push_back(out_block);
    persist_block(out_block);
    return true;
}

bool ImmutableLedger::verify_chain_integrity(std::string &error_msg) const {
    if (m_chain.empty()) return true;

    for (size_t i = 0; i < m_chain.size(); i++) {
        const LedgerBlock &blk = m_chain[i];
        if (blk.index != i) {
            error_msg = "Index mismatch at block " + std::to_string(i);
            return false;
        }

        std::string expected_prev = (i == 0) ?
            "0000000000000000000000000000000000000000000000000000000000000000" :
            m_chain[i - 1].block_hash;

        if (blk.prev_block_hash != expected_prev) {
            error_msg = "Chain broken between block " + std::to_string(i-1) + " and " + std::to_string(i);
            return false;
        }

        std::string recomputed_hash = calculate_block_hash(blk);
        if (blk.block_hash != recomputed_hash) {
            error_msg = "Tampering detected in block " + std::to_string(i) + "! Hash mismatch.";
            return false;
        }
    }
    return true;
}

std::vector<LedgerBlock> ImmutableLedger::get_all_blocks() const {
    return m_chain;
}

bool ImmutableLedger::export_json(const std::string &filepath) const {
    std::ofstream out(filepath.c_str());
    if (!out.is_open()) return false;

    out << "[\n";
    for (size_t i = 0; i < m_chain.size(); i++) {
        const LedgerBlock &b = m_chain[i];
        out << "  {\n";
        out << "    \"index\": " << b.index << ",\n";
        out << "    \"prev_block_hash\": \"" << b.prev_block_hash << "\",\n";
        out << "    \"timestamp\": \"" << b.timestamp << "\",\n";
        out << "    \"dispatch_id\": \"" << b.dispatch_id << "\",\n";
        out << "    \"sender_id\": \"" << b.sender_id << "\",\n";
        out << "    \"receiver_id\": \"" << b.receiver_id << "\",\n";
        out << "    \"payload_sha256\": \"" << b.payload_sha256 << "\",\n";
        out << "    \"watermark_proof\": \"" << b.watermark_proof << "\",\n";
        out << "    \"block_hash\": \"" << b.block_hash << "\"\n";
        out << "  }" << (i + 1 < m_chain.size() ? ",\n" : "\n");
    }
    out << "]\n";
    out.close();
    return true;
}
