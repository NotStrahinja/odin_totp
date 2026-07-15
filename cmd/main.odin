package main

import "../totp"
import "core:fmt"
import "core:os"
import "core:flags"

Options :: struct {
    secret: string `args:"pos=0,required" usage:"The base32 secret"`
}

main :: proc() {
    opt: Options

    flags.parse_or_exit(&opt, os.args)

    code, ok := totp.totp(opt.secret)

    if !ok {
        fmt.println("Failed to generate TOTP code")
    }

    fmt.printfln("Your code: %06d", code)
}
