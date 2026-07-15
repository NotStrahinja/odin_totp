package totp

import "core:crypto"
import "core:crypto/hmac"
import "core:crypto/hash"
import "core:encoding/base32"
import "core:time"

DIGIT_MOD := [9]u32{1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000}

htop :: proc(key: []u8, counter: u64, digits: u8, algorithm: hash.Algorithm = .Insecure_SHA1) -> u32 {
    message: [8]u8
    c := counter
    for i := 7; i >= 0; i -= 1 {
        message[i] = u8(c) & 0xFF
        c >>= 8
    }

    tag := make([]u8, hash.DIGEST_SIZES[algorithm])
    defer delete(tag)

    hmac.sum(algorithm, tag, message[:], key)

    offset := tag[len(tag) - 1] & 0x0F
    bin := (u32(tag[offset] & 0x7F) << 24) | (u32(tag[offset + 1]) << 16) | (u32(tag[offset + 2]) << 8) | u32(tag[offset + 3])

    return bin % DIGIT_MOD[digits]
}

totp :: proc(secret_b32: string, delay: i64 = 30, digits: u8 = 6, algorithm: hash.Algorithm = .Insecure_SHA1) -> (u32, bool) {
    decoded, dec_err := base32.decode(secret_b32)
    defer delete(decoded)
    if dec_err != nil {
        return 0, false
    }
    defer crypto.zero_explicit(raw_data(decoded), len(decoded))

    counter := u64(time.to_unix_seconds(time.now()) / delay)
    return htop(decoded, counter, digits, algorithm), true
}

verify :: proc(code: u32, secret_b32: string, delay: i64 = 30, digits: u8 = 6, algorithm: hash.Algorithm = .Insecure_SHA1, window: u8 = 1) -> bool {
    decoded, dec_err := base32.decode(secret_b32)
    defer delete(decoded)
    if dec_err != nil {
        return false
    }
    defer crypto.zero_explicit(raw_data(decoded), len(decoded))

    now := u64(time.to_unix_seconds(time.now()) / delay)

    for i := -i64(window); i <= i64(window); i += 1 {
        counter := u64(i64(now) + i)
        if htop(decoded, counter, digits, algorithm) == code {
            return true
        }
    }
    return false
}
