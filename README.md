# odin_totp
A simple TOTP implementation in Odin

A CLI tool for generating 30-second 6-digit codes is available and you can build it with the instructions below.

## How to use
You can build the CLI tool by running `build_win.bat` if you're on Windows, or `build.sh` if you're on Linux or macOS.

To use the library in your own project, just copy the entire `totp` directory and put it in the project root, then add this to your build script:

```sh
-collection:totp=.
```
