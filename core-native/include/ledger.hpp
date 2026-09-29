#ifndef LEDGER_HPP
#define LEDGER_HPP

#include <string>
#include <vector>
#include <cstdint>

struct LedgerBlock {
    uint32_t index;
    std::string prev_block_hash;
    std::string timestamp;
    std::string dispatch_id;
    std::string sender_id;
    std::string receiver_id;
    std::string payload_sha256;
    std::string watermark_proof;
    std::string block_hash;
};

class ImmutableLedger {
public:
    ImmutableLedger(const std::string &ledger_dir);

    // Appends a new verified dispatch block to the immutable ledger
    bool append_block(const std::string &dispatch_id,
                     const std::string &sender_id,
                     const std::string &receiver_id,
                     const std::string &payload_sha256,
                     const std::string &watermark_proof,
                     LedgerBlock &out_block);

    // Audits and verifies the complete chain integrity
    bool verify_chain_integrity(std::string &error_msg) const;

    // Retrieves all blocks
    std::vector<LedgerBlock> get_all_blocks() const;

    // Export audit log to JSON
    bool export_json(const std::string &filepath) const;

private:
    std::string m_storage_path;
    std::string m_json_export_path;
    std::vector<LedgerBlock> m_chain;

    void load_chain();
    void persist_block(const LedgerBlock &blk);
    static std::string calculate_block_hash(const LedgerBlock &blk);
};

#endif /* LEDGER_HPP */
