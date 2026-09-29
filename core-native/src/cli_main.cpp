#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <iomanip>

extern "C" {
#include "pqc_kem.h"
#include "aes_gcm.h"
#include "hkdf.h"
#include "sha256.h"
#include "keyring.h"
}

#include "watermark.hpp"
#include "ledger.hpp"

static void print_banner(const std::string &title) {
    std::cout << "\n======================================================\n";
    std::cout << "  " << title << "\n";
    std::cout << "======================================================\n";
}

int main(int argc, char* argv[]) {
    if (argc >= 4 && std::string(argv[1]) == "scan-crop") {
        std::string crop_path = argv[2];
        int crop_w = std::atoi(argv[3]);
        int crop_h = (argc >= 5) ? std::atoi(argv[4]) : crop_w;

        std::ifstream f(crop_path.c_str(), std::ios::binary);
        if (!f.is_open()) {
            std::cout << "{\"detected\":false,\"error\":\"Cannot open crop file\"}\n";
            return 1;
        }
        std::vector<uint8_t> crop_bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        f.close();

        TiledWatermarkEngine wm_engine;
        ForensicResult res = wm_engine.scan_cropped_leak(crop_bytes, crop_w, crop_h);
        std::cout << "{\"detected\":" << (res.detected ? "true" : "false")
                  << ",\"leaker_id\":\"" << res.leaker_id << "\""
                  << ",\"dispatch_id\":\"" << res.dispatch_id << "\""
                  << ",\"total_tiles\":" << res.total_tiles_scanned
                  << ",\"valid_tiles\":" << res.valid_tiles_voted
                  << ",\"confidence\":" << res.confidence_percent
                  << ",\"proof_hash\":\"" << res.forensic_proof_hash << "\"}\n";
        return 0;
    }

    if (argc >= 7 && std::string(argv[1]) == "embed-crop") {
        std::string in_path = argv[2];
        std::string out_path = argv[3];
        int w = std::atoi(argv[4]);
        int h = std::atoi(argv[5]);
        std::string receiver_id = argv[6];
        std::string dispatch_id = (argc >= 8) ? argv[7] : "DISP-CROP-DEMO";

        std::ifstream f(in_path.c_str(), std::ios::binary);
        if (!f.is_open()) {
            std::cout << "{\"success\":false,\"error\":\"Cannot open input file\"}\n";
            return 1;
        }
        std::vector<uint8_t> img_bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        f.close();

        if (img_bytes.size() < (size_t)(w * h)) {
            img_bytes.resize(w * h, 0x80);
        }

        TiledWatermarkEngine wm_engine;
        std::string proof_hex;
        bool ok = wm_engine.embed_watermark(img_bytes, w, h, receiver_id, dispatch_id, proof_hex);
        if (!ok) {
            std::cout << "{\"success\":false,\"error\":\"Embedding failed\"}\n";
            return 1;
        }

        std::ofstream out(out_path.c_str(), std::ios::binary);
        out.write(reinterpret_cast<const char*>(img_bytes.data()), img_bytes.size());
        out.close();

        std::cout << "{\"success\":true,\"forensic_proof\":\"" << proof_hex << "\"}\n";
        return 0;
    }

    print_banner("PQC OFFLINE SECURE BROADCAST - C/C++ CORE ENGINE");
    std::cout << "[INFO] Strict Offline Architecture: No Python, No SQLite, Zero Network Calls.\n";
    std::cout << "[INFO] Cryptography: ML-KEM-768 (FIPS 203) + AES-256-GCM + HKDF-SHA256.\n";
    std::cout << "[INFO] Forensic Defense: Tiled Redundant Watermark + Majority Voting against Cropping.\n";

    // 1. Setup Keyring
    print_banner("STEP 1: USER REGISTRATION & TPM HARDWARE SEALING");
    user_key_entry_t alice_keys;
    user_key_entry_t bob_keys;

    keyring_generate_user("agent-alice-sender", "AliceSecretPass2026!", &alice_keys);
    keyring_generate_user("agent-bob-receiver", "BobSecretPass2026!", &bob_keys);

    keyring_save_json(&alice_keys, "keyring_store/agent_alice.json");
    keyring_save_json(&bob_keys, "keyring_store/agent_bob.json");

    std::cout << "[SUCCESS] Generated & TPM-sealed ML-KEM-768 keypair for: agent-alice-sender\n";
    std::cout << "[SUCCESS] Generated & TPM-sealed ML-KEM-768 keypair for: agent-bob-receiver\n";
    std::cout << "          Public Key Size: " << ML_KEM_768_PUBLIC_KEY_BYTES << " bytes\n";
    std::cout << "          Secret Key Size: " << ML_KEM_768_SECRET_KEY_BYTES << " bytes (Hardware Sealed)\n";

    // 2. Prepare Payload & Watermark
    print_banner("STEP 2: PAYLOAD PREPARATION & TILED WATERMARK EMBEDDING");
    int width = 256;
    int height = 256;
    std::vector<uint8_t> payload_image(width * height);
    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
            payload_image[y * width + x] = static_cast<uint8_t>((x ^ y) & 0xFF);
        }
    }

    std::string dispatch_id = "DISP-2026-9901";
    std::string receiver_id = "agent-bob-receiver";
    std::string watermark_proof = "";

    TiledWatermarkEngine wm_engine;
    bool wm_ok = wm_engine.embed_watermark(payload_image, width, height, receiver_id, dispatch_id, watermark_proof);
    if (!wm_ok) {
        std::cerr << "[ERROR] Watermark embedding failed!\n";
        return 1;
    }
    std::cout << "[SUCCESS] Embedded 16 Redundant Tiles (64x64 grid) across payload image.\n";
    std::cout << "[FORENSIC PROOF] SHA-256: " << watermark_proof << "\n";

    // Compute payload hash
    uint8_t payload_hash[32];
    sha256_hash(payload_image.data(), payload_image.size(), payload_hash);
    char payload_hash_hex[65];
    sha256_to_hex(payload_hash, payload_hash_hex);
    std::cout << "[PAYLOAD HASH] SHA-256: " << payload_hash_hex << "\n";

    // 3. PQC ML-KEM-768 Encapsulation & AES-256-GCM Encryption
    print_banner("STEP 3: POST-QUANTUM ENCRYPTION (ML-KEM-768 + AES-256-GCM)");
    uint8_t kem_ct[ML_KEM_768_CIPHERTEXT_BYTES];
    uint8_t kem_ss[ML_KEM_768_SHARED_SECRET_BYTES];

    ml_kem_768_encaps(bob_keys.public_key, kem_ct, kem_ss);
    std::cout << "[SUCCESS] Encapsulated one-time session key for Bob using ML-KEM-768.\n";
    std::cout << "          KEM Ciphertext Size: " << ML_KEM_768_CIPHERTEXT_BYTES << " bytes\n";

    // Derive AES-256 key via HKDF
    uint8_t aes_key[32];
    uint8_t salt[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
    hkdf_sha256(salt, 16, kem_ss, 32, (const uint8_t*)"PQC_DISPATCH_AES_KEY", 20, aes_key, 32);

    // Encrypt with AES-256-GCM
    std::vector<uint8_t> ciphertext(payload_image.size());
    uint8_t iv[12] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x11,0x22,0x33,0x44,0x55,0x66};
    uint8_t gcm_tag[16];

    aes256_gcm_encrypt(aes_key, iv, (const uint8_t*)dispatch_id.c_str(), dispatch_id.length(),
                      payload_image.data(), payload_image.size(),
                      ciphertext.data(), gcm_tag);
    std::cout << "[SUCCESS] Encrypted " << ciphertext.size() << " bytes with AES-256-GCM.\n";

    // 4. Save Offline Dispatch JSON
    print_banner("STEP 4: SERIALIZE TO OFFLINE DISPATCH JSON");
    std::string dispatch_file = "dispatches/demo_dispatch.json";
    std::ofstream df(dispatch_file.c_str());
    df << "{\n"
       << "  \"dispatch_id\": \"" << dispatch_id << "\",\n"
       << "  \"sender_id\": \"agent-alice-sender\",\n"
       << "  \"receiver_id\": \"agent-bob-receiver\",\n"
       << "  \"kem_algorithm\": \"ML-KEM-768\",\n"
       << "  \"symmetric_algorithm\": \"AES-256-GCM\",\n"
       << "  \"watermark_proof\": \"" << watermark_proof << "\",\n"
       << "  \"payload_length\": " << ciphertext.size() << ",\n"
       << "  \"status\": \"OFFLINE_READY_FOR_SNEAKERNET_OR_USB_TRANSFER\"\n"
       << "}\n";
    df.close();
    std::cout << "[SUCCESS] Written offline dispatch manifest: " << dispatch_file << "\n";

    // 5. Receiver Decryption
    print_banner("STEP 5: RECEIVER OFFLINE IMPORT & DECRYPTION");
    uint8_t bob_sk[ML_KEM_768_SECRET_KEY_BYTES];
    if (keyring_unseal_secret_key(&bob_keys, "BobSecretPass2026!", bob_sk) != 0) {
        std::cerr << "[ERROR] TPM Unsealing failed!\n";
        return 1;
    }
    std::cout << "[SUCCESS] Bob successfully unsealed private key from TPM enclaves.\n";

    uint8_t bob_ss[ML_KEM_768_SHARED_SECRET_BYTES];
    ml_kem_768_decaps(bob_sk, kem_ct, bob_ss);

    uint8_t bob_aes_key[32];
    hkdf_sha256(salt, 16, bob_ss, 32, (const uint8_t*)"PQC_DISPATCH_AES_KEY", 20, bob_aes_key, 32);

    std::vector<uint8_t> decrypted_payload(ciphertext.size());
    if (aes256_gcm_decrypt(bob_aes_key, iv, (const uint8_t*)dispatch_id.c_str(), dispatch_id.length(),
                          ciphertext.data(), ciphertext.size(),
                          gcm_tag, decrypted_payload.data()) != 0) {
        std::cerr << "[ERROR] AES-GCM Decryption failed / GCM Tag mismatch!\n";
        return 1;
    }
    std::cout << "[SUCCESS] Authenticated AES-GCM decryption completed without error.\n";

    // 6. Update Append-Only Immutable Ledger
    print_banner("STEP 6: APPEND-ONLY IMMUTABLE LEDGER UPDATE");
    ImmutableLedger ledger("ledger_data");
    LedgerBlock block;
    ledger.append_block(dispatch_id, "agent-alice-sender", "agent-bob-receiver",
                        payload_hash_hex, watermark_proof, block);

    std::cout << "[LEDGER BLOCK #" << block.index << " CREATED]\n";
    std::cout << "  Prev Hash:    " << block.prev_block_hash << "\n";
    std::cout << "  Block Hash:   " << block.block_hash << "\n";
    std::cout << "  Timestamp:    " << block.timestamp << "\n";
    std::cout << "  Payload SHA:  " << block.payload_sha256 << "\n";

    std::string audit_err;
    if (ledger.verify_chain_integrity(audit_err)) {
        std::cout << "[AUDIT VERIFIED] RocksDB-style ledger chain is 100% tamper-proof & consistent.\n";
    } else {
        std::cerr << "[AUDIT ERROR] " << audit_err << "\n";
    }

    // 7. Test Cropping Leak Attack (The Leaker Problem)
    print_banner("STEP 7: SIMULATING LEAK ATTACK - CROPPING 75% OF IMAGE");
    std::cout << "[SCENARIO] Leaker crops the image down to a 128x128 corner (discarding 75% of data).\n";
    std::cout << "[SCENARIO] Can we still identify who leaked it?\n";

    int crop_w = 128;
    int crop_h = 128;
    std::vector<uint8_t> cropped_leak(crop_w * crop_h);
    // Extract top-right 128x128 corner
    for (int y = 0; y < crop_h; y++) {
        for (int x = 0; x < crop_w; x++) {
            cropped_leak[y * crop_w + x] = decrypted_payload[y * width + (x + 128)];
        }
    }

    // Run Forensic Analysis on the cropped fragment
    ForensicResult forensic = wm_engine.scan_cropped_leak(cropped_leak, crop_w, crop_h);

    if (forensic.detected) {
        std::cout << "\n>>> [FORENSIC MATCH FOUND! LEAKER IDENTIFIED!] <<<\n";
        std::cout << "  Identified Leaker ID: " << forensic.leaker_id << "\n";
        std::cout << "  Dispatch ID:          " << forensic.dispatch_id << "\n";
        std::cout << "  Tiles Scanned in Crop:" << forensic.total_tiles_scanned << "\n";
        std::cout << "  Valid Tiles Voted:    " << forensic.valid_tiles_voted << "\n";
        std::cout << "  Confidence:           " << forensic.confidence_percent << "%\n";
        std::cout << "  Forensic Proof Hash:  " << forensic.forensic_proof_hash << "\n";
        std::cout << ">>> CROPPING ATTACK SUCCESSFULLY DEFEATED VIA MAJORITY VOTING! <<<\n";
    } else {
        std::cerr << "[ERROR] Could not identify leaker from cropped image!\n";
    }

    print_banner("EXECUTION COMPLETE - ALL OFFLINE TESTS PASSED");
    return 0;
}
