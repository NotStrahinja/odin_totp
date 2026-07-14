package main

import "core:fmt"
import "core:crypto/hmac"
import "core:crypto/legacy/sha1"
import "core:os"
import "core:flags"
import "core:encoding/base32"
import "core:time"

Options :: struct {
    secret: string `args:"pos=0,required" usage:"The base32 secret"`
}

totp :: proc(secret_b32: string, delay: i64 = 30) -> u32 {
    decoded, dec_err := base32.decode(secret_b32)

    if dec_err != nil {
        fmt.println("Error: Failed to decode secret")
        return ~u32(0)
    }

    time_counter: u64 = u64(time.to_unix_seconds(time.now()) / delay)

    message: [8]u8

    for i := 7; i >= 0; i -= 1 {
        message[i] = u8(time_counter) & 0xFF
        time_counter >>= 8
    }

    tag := make([]u8, sha1.DIGEST_SIZE)
    defer delete(tag)

    hmac.sum(.Insecure_SHA1, tag, message[:], decoded)

    offset := tag[len(tag) - 1] & 0x0F
    bin := (u32(tag[offset] & 0x7F) << 24) | (u32(tag[offset + 1]) << 16) | (u32(tag[offset + 2]) << 8) | u32(tag[offset + 3])

    return bin % 1000000
}

main :: proc() {
    opt: Options

    flags.parse_or_exit(&opt, os.args)

    code := totp(opt.secret)

    fmt.printfln("Your code: %06d", code)
}
