# Stego

A steganography tool that hides data in PNG images using LSB (Least Significant Bit) technique.

## Features

- Hide files or text in PNG images
- Extract hidden data from images
- Extract from PNG URLs
- Data compression
- Optional ChaCha20-Poly1305 encryption
- Uses 2 LSBs per channel
- Automatic image sizing

## Building

```bash
make
```

Requires:
- libcurl (for URLs)
- zlib
- gcc/clang

On macOS:
```bash
brew install curl
```

## Usage

Hide a file:
```bash
stego hide input.txt output.png [-p password]
```

Hide text directly:
```bash
stego hide -t "Hello World" output.png [-p password]
```

Extract from file:
```bash
stego extract input.png output.txt [-p password]
```

Extract from URL:
```bash
stego -u https://example.com/secret.png -o output.txt [-p password]
```

## How it Works

Basic steganography implementation:
- Uses 2 LSBs from each RGB channel
- Requires 2 pixels per byte of data
- Compresses data before embedding
- Optional ChaCha20-Poly1305 encryption
- Creates or reuses PNG images as needed

### Storage

Storage characteristics:
- Compression typically reduces input size
- Uses 2 bits per color channel
- Requires 2 pixels per byte
- Image size scales with data size

## License

MIT License - see LICENSE file for details 