#include <iostream>
#include <vector>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <sstream>
#include <algorithm>

// CRC32 IEEE 802.3
static const uint32_t CRC32_POLY = 0xEDB88320;
static uint32_t crc32_table[256];
static bool crc_table_init = false;

static void init_crc32_table() {
    if (crc_table_init) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            c = (c & 1) ? (CRC32_POLY ^ (c >> 1)) : (c >> 1);
        }
        crc32_table[i] = c;
    }
    crc_table_init = true;
}

uint32_t compute_crc32(const uint8_t* data, size_t length) {
    init_crc32_table();
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

// 5-Bit Majority Voting: 1 Byte -> 40 Bits (5 repetitions per bit)
void majority_vote_encode(const std::vector<uint8_t>& in_data, std::vector<uint8_t>& out_bits) {
    out_bits.clear();
    for (size_t i = 0; i < in_data.size(); i++) {
        uint8_t byte = in_data[i];
        for (int b = 7; b >= 0; b--) {
            uint8_t bit = (byte >> b) & 1;
            for (int k = 0; k < 5; k++) {
                out_bits.push_back(bit);
            }
        }
    }
}

bool majority_vote_decode(const std::vector<uint8_t>& in_bits, std::vector<uint8_t>& out_data, int& corrected_bits) {
    out_data.clear();
    corrected_bits = 0;
    if (in_bits.size() % 40 != 0) return false;
    
    size_t num_bytes = in_bits.size() / 40;
    for (size_t i = 0; i < num_bytes; i++) {
        uint8_t byte_val = 0;
        for (int b = 0; b < 8; b++) {
            int ones = 0;
            for (int k = 0; k < 5; k++) {
                if (in_bits[i * 40 + b * 5 + k]) ones++;
            }
            uint8_t majority_bit = (ones >= 3) ? 1 : 0;
            if (ones > 0 && ones < 5) {
                corrected_bits += (majority_bit == 1) ? (5 - ones) : ones;
            }
            byte_val = (byte_val << 1) | majority_bit;
        }
        out_data.push_back(byte_val);
    }
    return true;
}

// 8x8 2D-DCT Constants
static const double PI = 3.14159265358979323846;
static double C[8];
static bool dct_init = false;

static void init_dct_constants() {
    if (dct_init) return;
    C[0] = 1.0 / std::sqrt(2.0);
    for (int i = 1; i < 8; i++) {
        C[i] = 1.0;
    }
    dct_init = true;
}

void forward_dct_8x8(const double in_block[8][8], double out_block[8][8]) {
    init_dct_constants();
    for (int u = 0; u < 8; u++) {
        for (int v = 0; v < 8; v++) {
            double sum = 0.0;
            for (int x = 0; x < 8; x++) {
                for (int y = 0; y < 8; y++) {
                    sum += in_block[x][y] * 
                           std::cos(((2 * x + 1) * u * PI) / 16.0) * 
                           std::cos(((2 * y + 1) * v * PI) / 16.0);
                }
            }
            out_block[u][v] = 0.25 * C[u] * C[v] * sum;
        }
    }
}

void inverse_dct_8x8(const double in_block[8][8], double out_block[8][8]) {
    init_dct_constants();
    for (int x = 0; x < 8; x++) {
        for (int y = 0; y < 8; y++) {
            double sum = 0.0;
            for (int u = 0; u < 8; u++) {
                for (int v = 0; v < 8; v++) {
                    sum += C[u] * C[v] * in_block[u][v] * 
                           std::cos(((2 * x + 1) * u * PI) / 16.0) * 
                           std::cos(((2 * y + 1) * v * PI) / 16.0);
                }
            }
            out_block[x][y] = 0.25 * sum;
        }
    }
}

static const double PYRAMID_SCALES[11] = {
    0.50, 0.65, 0.80, 0.90, 1.00, 1.10, 1.25, 1.40, 1.60, 1.80, 2.00
};

static const int PHASE_OFFSETS[16][2] = {
    {0, 0}, {0, 2}, {0, 4}, {0, 6},
    {2, 0}, {2, 2}, {2, 4}, {2, 6},
    {4, 0}, {4, 2}, {4, 4}, {4, 6},
    {6, 0}, {6, 2}, {6, 4}, {6, 6}
};

struct GrayscaleImage {
    int width;
    int height;
    std::vector<double> pixels;
    
    double get(int x, int y) const {
        if (x < 0) x = 0;
        if (x >= width) x = width - 1;
        if (y < 0) y = 0;
        if (y >= height) y = height - 1;
        return pixels[y * width + x];
    }
    
    void set(int x, int y, double val) {
        if (x >= 0 && x < width && y >= 0 && y < height) {
            pixels[y * width + x] = std::max(0.0, std::min(255.0, val));
        }
    }
};

GrayscaleImage resample_image(const GrayscaleImage& src, double scale) {
    int new_w = std::max(16, (int)(src.width * scale));
    int new_h = std::max(16, (int)(src.height * scale));
    GrayscaleImage dst;
    dst.width = new_w;
    dst.height = new_h;
    dst.pixels.resize(new_w * new_h, 0.0);
    
    for (int y = 0; y < new_h; y++) {
        for (int x = 0; x < new_w; x++) {
            double gx = (double)x / scale;
            double gy = (double)y / scale;
            int gxi = (int)gx;
            int gyi = (int)gy;
            double dx = gx - gxi;
            double dy = gy - gyi;
            
            double p00 = src.get(gxi, gyi);
            double p10 = src.get(gxi + 1, gyi);
            double p01 = src.get(gxi, gyi + 1);
            double p11 = src.get(gxi + 1, gyi + 1);
            
            double val = (1.0 - dx) * (1.0 - dy) * p00 +
                         dx * (1.0 - dy) * p10 +
                         (1.0 - dx) * dy * p01 +
                         dx * dy * p11;
            dst.set(x, y, val);
        }
    }
    return dst;
}

bool embed_watermark_image(GrayscaleImage& img, const std::vector<uint8_t>& raw_payload, double strength = 22.0) {
    std::vector<uint8_t> packet;
    packet.push_back('P');
    packet.push_back('Q');
    packet.push_back('C');
    packet.push_back('E');
    
    uint32_t len = (uint32_t)raw_payload.size();
    packet.push_back((len >> 24) & 0xFF);
    packet.push_back((len >> 16) & 0xFF);
    packet.push_back((len >> 8) & 0xFF);
    packet.push_back(len & 0xFF);
    
    packet.insert(packet.end(), raw_payload.begin(), raw_payload.end());
    
    uint32_t crc = compute_crc32(raw_payload.data(), raw_payload.size());
    packet.push_back((crc >> 24) & 0xFF);
    packet.push_back((crc >> 16) & 0xFF);
    packet.push_back((crc >> 8) & 0xFF);
    packet.push_back(crc & 0xFF);
    
    std::vector<uint8_t> bitstream;
    majority_vote_encode(packet, bitstream);
    
    int blocks_x = img.width / 8;
    int blocks_y = img.height / 8;
    int total_blocks = blocks_x * blocks_y;
    
    if ((int)bitstream.size() > total_blocks) {
        return false;
    }
    
    size_t bit_idx = 0;
    for (int by = 0; by < blocks_y && bit_idx < bitstream.size(); by++) {
        for (int bx = 0; bx < blocks_x && bit_idx < bitstream.size(); bx++) {
            double block[8][8];
            for (int r = 0; r < 8; r++) {
                for (int c = 0; c < 8; c++) {
                    block[r][c] = img.get(bx * 8 + c, by * 8 + r);
                }
            }
            
            double dct_block[8][8];
            forward_dct_8x8(block, dct_block);
            
            uint8_t bit = bitstream[bit_idx++];
            double diff = strength;
            if (bit == 1) {
                if (dct_block[3][3] <= dct_block[4][2] + diff) {
                    dct_block[3][3] = dct_block[4][2] + diff;
                }
            } else {
                if (dct_block[4][2] <= dct_block[3][3] + diff) {
                    dct_block[4][2] = dct_block[3][3] + diff;
                }
            }
            
            double idct_block[8][8];
            inverse_dct_8x8(dct_block, idct_block);
            
            for (int r = 0; r < 8; r++) {
                for (int c = 0; c < 8; c++) {
                    img.set(bx * 8 + c, by * 8 + r, idct_block[r][c]);
                }
            }
        }
    }
    return true;
}

struct ExtractionResult {
    bool success;
    int scale_index;
    double scale_val;
    int phase_index;
    int offset_x;
    int offset_y;
    int corrected_bits;
    uint32_t extracted_crc;
    uint32_t expected_crc;
    std::vector<uint8_t> payload;
};

bool extract_single_pass(const GrayscaleImage& img, int off_x, int off_y, int expected_stride_blocks, ExtractionResult& res) {
    int blocks_x = (img.width - off_x) / 8;
    int blocks_y = (img.height - off_y) / 8;
    if (blocks_x <= 0 || blocks_y <= 0) return false;
    
    int stride = (expected_stride_blocks > 0) ? expected_stride_blocks : blocks_x;
    
    std::vector<uint8_t> raw_bits;
    for (int by = 0; by < blocks_y; by++) {
        for (int bx = 0; bx < stride; bx++) {
            double block[8][8];
            for (int r = 0; r < 8; r++) {
                for (int c = 0; c < 8; c++) {
                    block[r][c] = img.get(off_x + bx * 8 + c, off_y + by * 8 + r);
                }
            }
            
            double dct_block[8][8];
            forward_dct_8x8(block, dct_block);
            
            uint8_t bit = (dct_block[3][3] > dct_block[4][2]) ? 1 : 0;
            raw_bits.push_back(bit);
        }
    }
    
    if (raw_bits.size() < 320) return false;
    
    for (size_t start_bit = 0; start_bit + 320 <= raw_bits.size(); start_bit += 5) {
        std::vector<uint8_t> test_bits(raw_bits.begin() + start_bit, raw_bits.begin() + start_bit + 160);
        std::vector<uint8_t> header_bytes;
        int corr = 0;
        if (!majority_vote_decode(test_bits, header_bytes, corr)) continue;
        
        if (header_bytes[0] == 'P' && header_bytes[1] == 'Q' && header_bytes[2] == 'C' && header_bytes[3] == 'E') {
            if (start_bit + 320 > raw_bits.size()) continue;
            std::vector<uint8_t> len_bits(raw_bits.begin() + start_bit + 160, raw_bits.begin() + start_bit + 320);
            std::vector<uint8_t> len_bytes;
            int corr_len = 0;
            majority_vote_decode(len_bits, len_bytes, corr_len);
            
            uint32_t payload_len = ((uint32_t)len_bytes[0] << 24) |
                                   ((uint32_t)len_bytes[1] << 16) |
                                   ((uint32_t)len_bytes[2] << 8)  |
                                   (uint32_t)len_bytes[3];
                                   
            if (payload_len > 65536) continue;
            
            size_t total_packet_bytes = 4 + 4 + payload_len + 4;
            size_t total_bits_needed = total_packet_bytes * 40;
            if (start_bit + total_bits_needed > raw_bits.size()) continue;
            
            std::vector<uint8_t> packet_bits(raw_bits.begin() + start_bit, raw_bits.begin() + start_bit + total_bits_needed);
            std::vector<uint8_t> packet_bytes;
            int total_corr = 0;
            if (!majority_vote_decode(packet_bits, packet_bytes, total_corr)) continue;
            
            std::vector<uint8_t> extracted_payload(packet_bytes.begin() + 8, packet_bytes.begin() + 8 + payload_len);
            size_t crc_offset = 8 + payload_len;
            uint32_t extracted_crc = ((uint32_t)packet_bytes[crc_offset] << 24) |
                                     ((uint32_t)packet_bytes[crc_offset + 1] << 16) |
                                     ((uint32_t)packet_bytes[crc_offset + 2] << 8)  |
                                     (uint32_t)packet_bytes[crc_offset + 3];
                                     
            uint32_t computed_crc = compute_crc32(extracted_payload.data(), extracted_payload.size());
            
            if (extracted_crc == computed_crc) {
                res.success = true;
                res.corrected_bits = total_corr;
                res.extracted_crc = extracted_crc;
                res.expected_crc = computed_crc;
                res.payload = extracted_payload;
                return true;
            }
        }
    }
    return false;
}

ExtractionResult forensic_pyramid_scan_176(const GrayscaleImage& suspect_img, int orig_block_stride = 0) {
    ExtractionResult best_res;
    best_res.success = false;
    best_res.scale_index = -1;
    best_res.phase_index = -1;
    best_res.corrected_bits = 0;
    
    for (int s_idx = 0; s_idx < 11; s_idx++) {
        double scale = PYRAMID_SCALES[s_idx];
        GrayscaleImage scaled_img = (std::abs(scale - 1.0) < 0.001) ? suspect_img : resample_image(suspect_img, scale);
        
        int stride = (orig_block_stride > 0) ? (int)(orig_block_stride * scale) : (scaled_img.width / 8);
        
        for (int p_idx = 0; p_idx < 16; p_idx++) {
            int off_x = PHASE_OFFSETS[p_idx][0];
            int off_y = PHASE_OFFSETS[p_idx][1];
            
            ExtractionResult res;
            if (extract_single_pass(scaled_img, off_x, off_y, stride, res) ||
                extract_single_pass(scaled_img, off_x, off_y, (scaled_img.width - off_x) / 8, res)) {
                res.scale_index = s_idx;
                res.scale_val = scale;
                res.phase_index = p_idx;
                res.offset_x = off_x;
                res.offset_y = off_y;
                return res;
            }
        }
    }
    return best_res;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "PQC-DCT Forensic Engine" << std::endl;
        return 0;
    }
    
    std::string cmd = argv[1];
    if (cmd == "test") {
        std::cout << "[*] Running Native C++ 2D-DCT & 176-Pass Pyramid Verification..." << std::endl;
        GrayscaleImage test_img;
        test_img.width = 512;
        test_img.height = 512;
        test_img.pixels.resize(512 * 512);
        for (int y = 0; y < 512; y++) {
            for (int x = 0; x < 512; x++) {
                test_img.pixels[y * 512 + x] = (x * 0.25 + y * 0.25 + (x % 32) * 2);
            }
        }
        
        std::string secret = "TOP-SECRET-PQC-FORENSIC-LEAK-ID-9941";
        std::vector<uint8_t> payload(secret.begin(), secret.end());
        
        std::cout << "[1] Embedding payload (" << payload.size() << " bytes) into 512x512 image..." << std::endl;
        bool ok = embed_watermark_image(test_img, payload, 25.0);
        if (!ok) {
            std::cout << "[-] Embedding failed!" << std::endl;
            return 1;
        }
        std::cout << "[+] Embedding successful. Simulating 1.0x camera snapshot + (2,4) sub-pixel shift..." << std::endl;
        
        GrayscaleImage shifted;
        shifted.width = test_img.width;
        shifted.height = test_img.height;
        shifted.pixels.resize(test_img.width * test_img.height, 0.0);
        for (int y = 0; y < test_img.height; y++) {
            for (int x = 0; x < test_img.width; x++) {
                shifted.set(x + 2, y + 4, test_img.get(x, y));
            }
        }
        
        std::cout << "[2] Running 176-Pass Forensic Pyramid Scanner..." << std::endl;
        ExtractionResult res = forensic_pyramid_scan_176(shifted, 64);
        if (res.success) {
            std::string recovered((char*)res.payload.data(), res.payload.size());
            std::cout << "[+] Forensic Recovery SUCCESS!" << std::endl;
            std::cout << "    - Matched Scale: " << res.scale_val << "x (Index " << res.scale_index << ")" << std::endl;
            std::cout << "    - Matched Phase Offset: (" << res.offset_x << ", " << res.offset_y << ")" << std::endl;
            std::cout << "    - Majority Vote Corrected Bits: " << res.corrected_bits << std::endl;
            std::cout << "    - CRC32 Validated: 0x" << std::hex << res.extracted_crc << std::dec << std::endl;
            std::cout << "    - Recovered Payload: " << recovered << std::endl;
            return 0;
        } else {
            std::cout << "[-] Forensic scan failed to locate watermark!" << std::endl;
            return 1;
        }
    }
    return 0;
}
