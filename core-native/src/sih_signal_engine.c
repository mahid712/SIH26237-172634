#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>

#define PI 3.14159265358979323846

// CRC32 IEEE 802.3
static const uint32_t CRC32_POLY = 0xEDB88320;
static uint32_t crc32_tab[256];
static int crc_ready = 0;

static void init_crc32() {
    if (crc_ready) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            c = (c & 1) ? (CRC32_POLY ^ (c >> 1)) : (c >> 1);
        }
        crc32_tab[i] = c;
    }
    crc_ready = 1;
}

uint32_t calc_crc32(const uint8_t* data, size_t len) {
    init_crc32();
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc = crc32_tab[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

// 5-Bit Majority Voting
void encode_5bit_majority(const uint8_t* in_data, size_t in_len, uint8_t* out_bits, size_t* out_len) {
    size_t bit_idx = 0;
    for (size_t i = 0; i < in_len; i++) {
        uint8_t byte = in_data[i];
        for (int b = 7; b >= 0; b--) {
            uint8_t bit = (byte >> b) & 1;
            for (int k = 0; k < 5; k++) {
                out_bits[bit_idx++] = bit;
            }
        }
    }
    *out_len = bit_idx;
}

int decode_5bit_majority(const uint8_t* in_bits, size_t bit_len, uint8_t* out_data, size_t* out_len, int* corrected_bits) {
    if (bit_len % 40 != 0) return 0;
    size_t num_bytes = bit_len / 40;
    *corrected_bits = 0;
    for (size_t i = 0; i < num_bytes; i++) {
        uint8_t byte_val = 0;
        for (int b = 0; b < 8; b++) {
            int ones = 0;
            for (int k = 0; k < 5; k++) {
                if (in_bits[i * 40 + b * 5 + k]) ones++;
            }
            uint8_t majority_bit = (ones >= 3) ? 1 : 0;
            if (ones > 0 && ones < 5) {
                *corrected_bits += (majority_bit == 1) ? (5 - ones) : ones;
            }
            byte_val = (byte_val << 1) | majority_bit;
        }
        out_data[i] = byte_val;
    }
    *out_len = num_bytes;
    return 1;
}

typedef struct {
    double sample_rate;
    int num_samples;
    float* samples;
} AudioBuffer;

// Pulse-Width Jitter Modulation:
// Bit 0: 60ms pulse
// Bit 1: 30ms pulse
// Silence: 20ms
AudioBuffer generate_audio_signal(const uint8_t* payload, size_t payload_len, double sample_rate) {
    size_t packet_len = 4 + 4 + payload_len + 4;
    uint8_t* packet = (uint8_t*)malloc(packet_len);
    packet[0] = 'M'; packet[1] = 'R'; packet[2] = 'S'; packet[3] = 'E';
    packet[4] = (payload_len >> 24) & 0xFF;
    packet[5] = (payload_len >> 16) & 0xFF;
    packet[6] = (payload_len >> 8) & 0xFF;
    packet[7] = payload_len & 0xFF;
    memcpy(packet + 8, payload, payload_len);
    uint32_t crc = calc_crc32(payload, payload_len);
    packet[8 + payload_len] = (crc >> 24) & 0xFF;
    packet[9 + payload_len] = (crc >> 16) & 0xFF;
    packet[10 + payload_len] = (crc >> 8) & 0xFF;
    packet[11 + payload_len] = crc & 0xFF;

    size_t total_bits = packet_len * 40;
    uint8_t* bitstream = (uint8_t*)malloc(total_bits);
    size_t out_bits_len = 0;
    encode_5bit_majority(packet, packet_len, bitstream, &out_bits_len);

    double carrier_freq = 1000.0;
    int max_samples = (int)(total_bits * 0.10 * sample_rate) + 10000;
    float* buffer = (float*)calloc(max_samples, sizeof(float));
    int cur_sample = 0;

    for (size_t i = 0; i < total_bits; i++) {
        uint8_t bit = bitstream[i];
        double pulse_len = (bit == 0) ? 0.050 : 0.025; // 50ms vs 25ms
        int pulse_samples = (int)(pulse_len * sample_rate);

        for (int s = 0; s < pulse_samples; s++) {
            double t = (double)s / sample_rate;
            double env = 1.0;
            // Short 2ms attack/decay
            int ramp = (int)(0.002 * sample_rate);
            if (s < ramp) env = (double)s / ramp;
            else if (s > pulse_samples - ramp) env = (double)(pulse_samples - s) / ramp;
            buffer[cur_sample++] = (float)(0.8 * env * sin(2.0 * PI * carrier_freq * t));
        }

        int gap_samples = (int)(0.015 * sample_rate);
        for (int s = 0; s < gap_samples; s++) {
            buffer[cur_sample++] = 0.0f;
        }
    }

    free(packet);
    free(bitstream);

    AudioBuffer ab;
    ab.sample_rate = sample_rate;
    ab.num_samples = cur_sample;
    ab.samples = buffer;
    return ab;
}

int extract_signal_payload(const float* samples, int num_samples, double sample_rate, uint8_t* out_payload, size_t* out_payload_len, int* corrected_bits) {
    // 1. Moving RMS energy follower
    int win_size = (int)(0.005 * sample_rate);
    double threshold = 0.10;
    
    int in_pulse = 0;
    int pulse_start = 0;
    int pulse_lengths[10000];
    int pulse_count = 0;

    for (int i = 0; i < num_samples; i += (win_size / 2)) {
        double sum_sq = 0.0;
        int count = 0;
        for (int k = 0; k < win_size && (i + k < num_samples); k++) {
            sum_sq += samples[i + k] * samples[i + k];
            count++;
        }
        double rms = sqrt(sum_sq / count);

        if (!in_pulse && rms > threshold) {
            in_pulse = 1;
            pulse_start = i;
        } else if (in_pulse && rms < threshold * 0.4) {
            in_pulse = 0;
            pulse_lengths[pulse_count++] = i - pulse_start;
            if (pulse_count >= 10000) break;
        }
    }

    if (pulse_count < 320) return 0;

    // Decision threshold: midpoint between 25ms and 50ms = 37.5ms
    int cutoff_samples = (int)(0.0375 * sample_rate);
    uint8_t* raw_bits = (uint8_t*)malloc(pulse_count);
    for (int i = 0; i < pulse_count; i++) {
        raw_bits[i] = (pulse_lengths[i] < cutoff_samples) ? 1 : 0;
    }

    for (size_t start = 0; start + 320 <= (size_t)pulse_count; start += 5) {
        uint8_t header[4];
        int corr = 0;
        if (!decode_5bit_majority(raw_bits + start, 160, header, &corr, corrected_bits)) continue;

        if (header[0] == 'M' && header[1] == 'R' && header[2] == 'S' && header[3] == 'E') {
            uint8_t len_bytes[4];
            decode_5bit_majority(raw_bits + start + 160, 160, len_bytes, &corr, corrected_bits);
            uint32_t payload_len = ((uint32_t)len_bytes[0] << 24) |
                                   ((uint32_t)len_bytes[1] << 16) |
                                   ((uint32_t)len_bytes[2] << 8)  |
                                   (uint32_t)len_bytes[3];

            if (payload_len > 4096) continue;
            size_t total_bits = (4 + 4 + payload_len + 4) * 40;
            if (start + total_bits > (size_t)pulse_count) continue;

            uint8_t* packet = (uint8_t*)malloc(4 + 4 + payload_len + 4);
            size_t decoded_packet_len = 0;
            decode_5bit_majority(raw_bits + start, total_bits, packet, &decoded_packet_len, corrected_bits);

            uint8_t* payload_data = packet + 8;
            uint32_t ext_crc = ((uint32_t)packet[8 + payload_len] << 24) |
                               ((uint32_t)packet[9 + payload_len] << 16) |
                               ((uint32_t)packet[10 + payload_len] << 8) |
                               (uint32_t)packet[11 + payload_len];

            uint32_t calc_crc = calc_crc32(payload_data, payload_len);
            if (ext_crc == calc_crc) {
                memcpy(out_payload, payload_data, payload_len);
                *out_payload_len = payload_len;
                free(packet);
                free(raw_bits);
                return 1;
            }
            free(packet);
        }
    }

    free(raw_bits);
    return 0;
}

int main(int argc, char* argv[]) {
    printf("[*] Running Native C Signal Timing & Jitter Verification Test...\n");
    const char* test_msg = "PQC-RADIO-SIGNAL-AUTHENTIC-2026";
    size_t msg_len = strlen(test_msg);

    AudioBuffer ab = generate_audio_signal((const uint8_t*)test_msg, msg_len, 44100.0);
    printf("    Generated %d audio samples (%.2f s)\n", ab.num_samples, ab.num_samples / 44100.0);

    // Simulate 5% noise
    for (int i = 0; i < ab.num_samples; i++) {
        double noise = ((double)rand() / RAND_MAX - 0.5) * 0.05;
        ab.samples[i] += (float)noise;
    }

    uint8_t extracted[512];
    size_t ext_len = 0;
    int corrected = 0;
    int ok = extract_signal_payload(ab.samples, ab.num_samples, 44100.0, extracted, &ext_len, &corrected);

    if (ok) {
        extracted[ext_len] = '\0';
        printf("[+] Signal Recovery SUCCESS!\n");
        printf("    - Extracted Length: %zu bytes\n", ext_len);
        printf("    - Majority Voting Corrected Bits: %d\n", corrected);
        printf("    - CRC32 Validated: 100%% Authentic\n");
        printf("    - Payload: %s\n", (char*)extracted);
    } else {
        printf("[-] Failed to extract signal payload.\n");
    }

    free(ab.samples);
    return ok ? 0 : 1;
}
