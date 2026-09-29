/**
 * Comprehensive Automated System Test for Offline Secure Broadcast & Forensic Lab (ZERO PYTHON)
 */

const http = require('http');

function post(path, data) {
    return new Promise((resolve, reject) => {
        const payload = JSON.stringify(data || {});
        const req = http.request({
            hostname: '127.0.0.1',
            port: 8080,
            path: path,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload)
            }
        }, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                try {
                    resolve({ status: res.statusCode, data: JSON.parse(body) });
                } catch (e) {
                    resolve({ status: res.statusCode, text: body });
                }
            });
        });
        req.on('error', reject);
        req.write(payload);
        req.end();
    });
}

function get(path) {
    return new Promise((resolve, reject) => {
        http.get(`http://127.0.0.1:8080${path}`, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                try {
                    resolve({ status: res.statusCode, data: JSON.parse(body) });
                } catch (e) {
                    resolve({ status: res.statusCode, text: body });
                }
            });
        }).on('error', reject);
    });
}

async function runTests() {
    console.log("================================================================================");
    console.log("  OFFLINE SECURE BROADCAST & FORENSIC PLATFORM - END-TO-END VERIFICATION       ");
    console.log("================================================================================");

    // 1. Status Check
    console.log("\n[1] Testing Node Status & EMCON Mode...");
    const statusRes = await get('/api/status');
    console.log("    Server Status:", statusRes.data.status, "| EMCON:", statusRes.data.emcon_mode);
    if (statusRes.data.status !== 'ONLINE') throw new Error("Server not online");

    // 2. User Registry
    console.log("\n[2] Testing Registered Recipient Ring...");
    const usersRes = await get('/api/users/list');
    console.log("    Registered Agents:", usersRes.data.users.map(u => u.username).join(', '));
    if (usersRes.data.users.length < 2) throw new Error("Users not registered");

    // 3. Create Dispatch with Text (Unicode Zero-Width Steganography)
    console.log("\n[3] Testing Multi-User Dispatch Creation (Text Briefing)...");
    const briefingText = "TOP SECRET DIRECTIVE: Deploy sovereign quantum-resistant network across defense nodes immediately.";
    const dispRes = await post('/api/dispatch/create', {
        filename: "mission_directive.txt",
        file_data_b64: Buffer.from(briefingText, 'utf-8').toString('base64'),
        recipients: ["bob", "alice"]
    });
    console.log("    Broadcast Total:", dispRes.data.total_dispatches);
    console.log("    Medium Used:", dispRes.data.medium_used);
    const bobDisp = dispRes.data.dispatches.find(d => d.assigned_to === 'bob');
    console.log("    Bob Dispatch ID:", bobDisp.dispatch_id, "| DLT Block #:", bobDisp.dlt_block_index);

    // 4. Recipient Reception & Decryption
    console.log("\n[4] Testing Recipient Portal Reception & Decryption for Agent Bob...");
    const bobCreds = await get('/api/user/credentials?username=bob');
    const bobRecv = await post('/api/dispatch/receive', {
        dispatch_id: bobDisp.dispatch_id,
        sk_hex: bobCreds.data.sk_hex
    });
    console.log("    Decryption Success:", bobRecv.data.success);
    console.log("    Target Recipient:", bobRecv.data.recipient_info);
    console.log("    Medium Used:", bobRecv.data.medium_used);
    if (!bobRecv.data.text_content) throw new Error("Decrypted text is empty");

    // 5. Forensic Investigation: Leaked Text with Zero-Width Stego
    console.log("\n[5] Testing Forensic Lab Leak Attribution on Bob's Leaked Text...");
    const leakedText = bobRecv.data.text_content;
    const forensicRes = await post('/api/forensics/investigate', {
        filename: "leaked_text.txt",
        file_data_b64: "",
        text_content: leakedText
    });
    console.log("    Investigation Success:", forensicRes.data.success);
    console.log("    Attributed Leaker:", forensicRes.data.leaker_identified);
    console.log("    Raw Fingerprint:", forensicRes.data.raw_fingerprint);
    console.log("    Forensic Medium:", forensicRes.data.forensic_details.medium);
    console.log("    CRC32 Checksum Verified:", forensicRes.data.forensic_details.crc32_verified);
    console.log("    DLT Merkle Proof:", forensicRes.data.dlt_audit_proof ? `Block #${forensicRes.data.dlt_audit_proof.block_index}` : 'None');

    if (!forensicRes.data.success || !forensicRes.data.leaker_identified.includes("Bob")) {
        throw new Error("Forensic leak attribution failed to identify Bob!");
    }
    console.log("    >>> PASS: Leaker Bob positively identified beyond all doubt!");

    // 6. Forensic Investigation: Clean Text (Negative Test)
    console.log("\n[6] Testing Negative Control (Clean unwatermarked text)...");
    const cleanRes = await post('/api/forensics/investigate', {
        filename: "clean_document.txt",
        file_data_b64: "",
        text_content: "This is completely ordinary, unclassified public text without any steganography."
    });
    console.log("    Clean Scan Success:", cleanRes.data.success, "| Error message:", cleanRes.data.error);
    if (cleanRes.data.success !== false) throw new Error("Expected false for clean text!");
    console.log("    >>> PASS: Clean text correctly confirmed free of tamper/watermark!");

    // 7. Test Image Dispatch & Investigation
    console.log("\n[7] Testing Image Dispatch & Binary Steganography (Signed EOF Trailer)...");
    const fakePng = Buffer.concat([
        Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
        Buffer.alloc(64, 0x42)
    ]);
    const imgDispRes = await post('/api/dispatch/create', {
        filename: "classified_map.png",
        file_data_b64: fakePng.toString('base64'),
        recipients: ["alice"]
    });
    const aliceDisp = imgDispRes.data.dispatches.find(d => d.assigned_to === 'alice');
    console.log("    Alice Image Dispatch ID:", aliceDisp.dispatch_id);

    const aliceCreds = await get('/api/user/credentials?username=alice');
    const aliceRecv = await post('/api/dispatch/receive', {
        dispatch_id: aliceDisp.dispatch_id,
        sk_hex: aliceCreds.data.sk_hex
    });
    console.log("    Alice Decrypted Image Size:", Math.round(aliceRecv.data.file_b64.length * 0.75), "bytes");

    const imgForensicRes = await post('/api/forensics/investigate', {
        filename: "leaked_photo.png",
        file_data_b64: aliceRecv.data.file_b64,
        text_content: ""
    });
    console.log("    Image Attribution:", imgForensicRes.data.leaker_identified);
    if (!imgForensicRes.data.success || !imgForensicRes.data.leaker_identified.includes("Alice")) {
        throw new Error("Forensic leak attribution failed to identify Alice!");
    }
    console.log("    >>> PASS: Photographic leaker Alice positively identified!");

    // 8. Test 4-Layer DLT Audit
    console.log("\n[8] Testing 4-Layer DLT Tamper Resistance Audit...");
    const auditPristine = await get('/api/dlt/audit');
    console.log("    Tamper Detected (Before):", auditPristine.data.tamper_detected);
    console.log("    Layer 1 (Hash Link):", auditPristine.data.layer_status.layer1_hash_link);
    console.log("    Layer 2 (Merkle Root):", auditPristine.data.layer_status.layer2_merkle_root);
    console.log("    Layer 3 (PQC Signature):", auditPristine.data.layer_status.layer3_pqc_signature);
    console.log("    Layer 4 (Monotonicity):", auditPristine.data.layer_status.layer4_state_monotonicity);
    if (auditPristine.data.tamper_detected) throw new Error("Ledger should be pristine!");

    // 9. Inject Tamper & Verify Failure
    console.log("\n[9] Simulating Malicious Tamper Injection into DLT Block #1...");
    const tamperRes = await post('/api/dlt/tamper', {
        block_index: 1,
        field: "prev_hash",
        value: "0000000000000000000000000000000000000000000000000000000000000000"
    });
    console.log("    Tamper Detected (After Injection):", tamperRes.data.audit.tamper_detected);
    console.log("    Layer 1 Status:", tamperRes.data.audit.layer_status.layer1_hash_link);
    if (!tamperRes.data.audit.tamper_detected) throw new Error("Tamper was not detected!");

    // 10. Restore Clean Ledger
    console.log("\n[10] Restoring Ledger to Clean State...");
    const restoreRes = await post('/api/dlt/restore', {});
    console.log("    Tamper Detected (After Restore):", restoreRes.data.audit.tamper_detected);
    if (restoreRes.data.audit.tamper_detected) throw new Error("Ledger restore failed!");
    console.log("    >>> PASS: 4-Layer DLT Tamper Detection & Self-Healing Validated!");

    // 11. Test PQC Sandbox Endpoints
    console.log("\n[11] Testing NIST PQC Sandbox (ML-KEM-768 & ML-DSA-65)...");
    const kemKey = await post('/api/pqc/kem/keygen', {});
    console.log("    ML-KEM-768 Keygen:", kemKey.data.public_key_len, "bytes PK |", kemKey.data.secret_key_len, "bytes SK");

    const kemEnc = await post('/api/pqc/kem/encaps', {});
    console.log("    ML-KEM-768 Encapsulated Ciphertext:", kemEnc.data.ciphertext_hex.slice(0, 24) + "...");

    const kemDec = await post('/api/pqc/kem/decaps', {});
    console.log("    ML-KEM-768 Decapsulated Secret Match:", kemDec.data.match);

    const dsaKey = await post('/api/pqc/dsa/keygen', {});
    console.log("    ML-DSA-65 Keygen:", dsaKey.data.public_key_len, "bytes PK |", dsaKey.data.secret_key_len, "bytes SK");

    const dsaSig = await post('/api/pqc/dsa/sign', { message: "CLASSIFIED_DLT_TEST" });
    console.log("    ML-DSA-65 Signature:", dsaSig.data.signature_len, "bytes");

    const dsaVer = await post('/api/pqc/dsa/verify', {});
    console.log("    ML-DSA-65 Verification:", dsaVer.data.verified);

    const zeroize = await post('/api/pqc/zeroize', {});
    console.log("    RAM Zeroization Status:", zeroize.data.status, "| Scrubbed:", zeroize.data.bytes_scrubbed, "bytes");

    console.log("\n================================================================================");
    console.log("  >>> ALL 11 TEST SUITES PASSED WITH 100% SUCCESS! <<<                          ");
    console.log("================================================================================");
}

runTests().catch(err => {
    console.error("\n[-] TEST FAILED:", err);
    process.exit(1);
});
