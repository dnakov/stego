# Stego

A simple steganography tool that hides data in PNG images using LSB (Least Significant Bit) technique with optional encryption.

## Features

- Hide files or text in PNG images
- Extract hidden data from images
- Optional password encryption using ChaCha20-Poly1305
- Efficient bit usage (1 LSB per channel across 3 pixels)
- No visible artifacts in the output image

## Building

```bash
make
```

## Usage

Hide a file:
```bash
stego hide input.txt output.png -p secret
```

Hide text directly:
```bash
stego hide -t "Hello World" output.png -p secret
```

Extract data:
```bash
stego extract output.png extracted.txt -p secret
```

## How it Works

The tool uses the least significant bit (LSB) of each RGB channel to store data. For each byte of data:
- Uses 1 LSB from each channel (R,G,B) across 3 pixels
- This allows for 8 bits of data to be stored in 3 pixels
- The pattern is designed to minimize visible artifacts
- Optional encryption using ChaCha20-Poly1305 for security

## License

MIT License - see LICENSE file for details 