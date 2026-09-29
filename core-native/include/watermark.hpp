#ifndef WATERMARK_HPP
#define WATERMARK_HPP

#include <vector>
#include <string>
#include <cstdint>
#include <map>

#pragma pack(push, 1)
struct WatermarkPayload {
    char magic[4];          // "WMPQ"
    char receiver_id[32];   // Leaker identification
    char dispatch_id[16];   // Dispatch UUID
    uint64_t timestamp;     // Dispatch timestamp
    uint32_t checksum;      // CRC32 checksum
};
#pragma pack(pop)

struct ForensicResult {
    bool detected;
    std::string leaker_id;
    std::string dispatch_id;
    uint32_t total_tiles_scanned;
    uint32_t valid_tiles_voted;
    double confidence_percent;
    std::string forensic_proof_hash;
};

class TiledWatermarkEngine {
public:
    static const int TILE_SIZE = 64; // 64x64 pixels per tile for maximum crop-resistance

    TiledWatermarkEngine();

    // Embeds the redundant tiled watermark across the entire image buffer
    bool embed_watermark(std::vector<uint8_t> &image_data, int width, int height,
                        const std::string &receiver_id, const std::string &dispatch_id,
                        std::string &out_forensic_proof);

    // Forensic Scanner: scans ANY cropped portion of the image and identifies leaker via majority voting
    ForensicResult scan_cropped_leak(const std::vector<uint8_t> &cropped_data, int crop_w, int crop_h);

    // Compute CRC32
    static uint32_t compute_crc32(const uint8_t *data, size_t len);

private:
    void embed_in_tile(uint8_t *tile_pixels, int stride, const WatermarkPayload &payload);
    bool extract_from_tile(const uint8_t *tile_pixels, int stride, WatermarkPayload &out_payload);
};

#endif /* WATERMARK_HPP */
