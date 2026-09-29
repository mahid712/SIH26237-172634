#include "watermark.hpp"
extern "C" {
#include "sha256.h"
}
#include <cstring>
#include <cmath>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <iomanip>

uint32_t TiledWatermarkEngine::compute_crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    return ~crc;
}

TiledWatermarkEngine::TiledWatermarkEngine() {}

void TiledWatermarkEngine::embed_in_tile(uint8_t *tile_pixels, int stride, const WatermarkPayload &payload) {
    const uint8_t *raw = reinterpret_cast<const uint8_t*>(&payload);
    size_t payload_len = sizeof(WatermarkPayload);

    // Embed bits into LSB / mid-frequency positions of the 64x64 tile
    // 64x64 has 4096 pixels; payload is ~64 bytes (512 bits)
    // 8x redundancy per tile!
    for (size_t bit_idx = 0; bit_idx < payload_len * 8; bit_idx++) {
        uint8_t byte = raw[bit_idx / 8];
        int bit = (byte >> (bit_idx % 8)) & 1;

        // Repeat bit across multiple pixel positions in tile
        for (int rep = 0; rep < 4; rep++) {
            int px = 4 + (bit_idx % 56);
            int py = 4 + ((bit_idx / 56) * 4 + rep) % 56;
            int offset = py * stride + px;

            uint8_t val = tile_pixels[offset];
            tile_pixels[offset] = (val & 0xFE) | (uint8_t)bit;
        }
    }
}

bool TiledWatermarkEngine::extract_from_tile(const uint8_t *tile_pixels, int stride, WatermarkPayload &out_payload) {
    uint8_t raw[sizeof(WatermarkPayload)] = {0};
    size_t payload_len = sizeof(WatermarkPayload);

    for (size_t bit_idx = 0; bit_idx < payload_len * 8; bit_idx++) {
        int ones = 0;
        int zeros = 0;

        for (int rep = 0; rep < 4; rep++) {
            int px = 4 + (bit_idx % 56);
            int py = 4 + ((bit_idx / 56) * 4 + rep) % 56;
            int offset = py * stride + px;

            if (tile_pixels[offset] & 1) ones++;
            else zeros++;
        }

        if (ones > zeros) {
            raw[bit_idx / 8] |= (1 << (bit_idx % 8));
        }
    }

    WatermarkPayload *candidate = reinterpret_cast<WatermarkPayload*>(raw);

    // Verify Magic header
    if (std::memcmp(candidate->magic, "WMPQ", 4) != 0) {
        return false;
    }

    // Verify CRC32
    uint32_t expected_crc = compute_crc32(raw, sizeof(WatermarkPayload) - sizeof(uint32_t));
    if (candidate->checksum != expected_crc) {
        return false;
    }

    out_payload = *candidate;
    return true;
}

bool TiledWatermarkEngine::embed_watermark(std::vector<uint8_t> &image_data, int width, int height,
                                         const std::string &receiver_id, const std::string &dispatch_id,
                                         std::string &out_forensic_proof) {
    if (width < TILE_SIZE || height < TILE_SIZE) return false;

    WatermarkPayload payload;
    std::memset(&payload, 0, sizeof(payload));
    std::memcpy(payload.magic, "WMPQ", 4);

    std::memset(payload.receiver_id, 0, sizeof(payload.receiver_id));
    std::strncpy(payload.receiver_id, receiver_id.c_str(), sizeof(payload.receiver_id) - 1);

    std::memset(payload.dispatch_id, 0, sizeof(payload.dispatch_id));
    std::strncpy(payload.dispatch_id, dispatch_id.c_str(), sizeof(payload.dispatch_id) - 1);

    payload.timestamp = static_cast<uint64_t>(time(NULL));
    payload.checksum = compute_crc32(reinterpret_cast<const uint8_t*>(&payload),
                                     sizeof(WatermarkPayload) - sizeof(uint32_t));

    int tiles_x = width / TILE_SIZE;
    int tiles_y = height / TILE_SIZE;

    // Embed into every single grid tile (Wallpaper Redundancy)
    for (int ty = 0; ty < tiles_y; ty++) {
        for (int tx = 0; tx < tiles_x; tx++) {
            uint8_t *tile_start = image_data.data() + (ty * TILE_SIZE * width + tx * TILE_SIZE);
            embed_in_tile(tile_start, width, payload);
        }
    }

    // Generate cryptographic forensic proof
    uint8_t proof_hash[32];
    sha256_hash(reinterpret_cast<const uint8_t*>(&payload), sizeof(payload), proof_hash);
    char hex[65];
    sha256_to_hex(proof_hash, hex);
    out_forensic_proof = std::string(hex);

    return true;
}

ForensicResult TiledWatermarkEngine::scan_cropped_leak(const std::vector<uint8_t> &cropped_data, int crop_w, int crop_h) {
    ForensicResult res;
    res.detected = false;
    res.total_tiles_scanned = 0;
    res.valid_tiles_voted = 0;
    res.confidence_percent = 0.0;

    if (crop_w < TILE_SIZE || crop_h < TILE_SIZE) {
        return res; // Cropped portion too tiny for single 64x64 tile
    }

    int best_ox = 0;
    int best_oy = 0;
    bool found_phase = false;

    // Fast Pass: Check aligned at (0, 0)
    int initial_tiles_x = crop_w / TILE_SIZE;
    int initial_tiles_y = crop_h / TILE_SIZE;
    for (int ty = 0; ty < initial_tiles_y && !found_phase; ty++) {
        for (int tx = 0; tx < initial_tiles_x && !found_phase; tx++) {
            const uint8_t *sample_tile = cropped_data.data() + (ty * TILE_SIZE * crop_w + tx * TILE_SIZE);
            WatermarkPayload test_payload;
            if (extract_from_tile(sample_tile, crop_w, test_payload)) {
                best_ox = 0;
                best_oy = 0;
                found_phase = true;
                break;
            }
        }
    }

    // Sub-tile Sliding Pass: Search arbitrary crop shift offsets (ox, oy)
    if (!found_phase) {
        for (int oy = 0; oy < TILE_SIZE && !found_phase; oy++) {
            if (crop_h - oy < TILE_SIZE) break;
            for (int ox = 0; ox < TILE_SIZE && !found_phase; ox++) {
                if (crop_w - ox < TILE_SIZE) break;
                const uint8_t *sample_tile = cropped_data.data() + (oy * crop_w + ox);
                WatermarkPayload test_payload;
                if (extract_from_tile(sample_tile, crop_w, test_payload)) {
                    best_ox = ox;
                    best_oy = oy;
                    found_phase = true;
                    break;
                }
            }
        }
    }

    if (!found_phase) {
        return res; // No authentic tiled watermark found
    }

    int tiles_x = (crop_w - best_ox) / TILE_SIZE;
    int tiles_y = (crop_h - best_oy) / TILE_SIZE;
    res.total_tiles_scanned = tiles_x * tiles_y;

    std::map<std::string, int> votes;
    std::map<std::string, std::string> dispatch_map;

    for (int ty = 0; ty < tiles_y; ty++) {
        for (int tx = 0; tx < tiles_x; tx++) {
            const uint8_t *tile_start = cropped_data.data() + ((best_oy + ty * TILE_SIZE) * crop_w + (best_ox + tx * TILE_SIZE));
            WatermarkPayload extracted;
            if (extract_from_tile(tile_start, crop_w, extracted)) {
                std::string rec_id(extracted.receiver_id);
                std::string disp_id(extracted.dispatch_id);
                votes[rec_id]++;
                dispatch_map[rec_id] = disp_id;
                res.valid_tiles_voted++;
            }
        }
    }

    if (!votes.empty()) {
        int max_votes = 0;
        std::string winner_id = "";
        for (const auto &pair : votes) {
            if (pair.second > max_votes) {
                max_votes = pair.second;
                winner_id = pair.first;
            }
        }

        res.detected = true;
        res.leaker_id = winner_id;
        res.dispatch_id = dispatch_map[winner_id];
        res.confidence_percent = (static_cast<double>(max_votes) / res.valid_tiles_voted) * 100.0;

        uint8_t proof[32];
        sha256_hash(reinterpret_cast<const uint8_t*>(winner_id.c_str()), winner_id.length(), proof);
        char hex[65];
        sha256_to_hex(proof, hex);
        res.forensic_proof_hash = std::string(hex);
    }

    return res;
}
