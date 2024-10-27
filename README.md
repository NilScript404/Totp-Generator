# Minimal TOTP Generator

## Overview
A lightweight Time-based One-Time Password (TOTP) generator implemented in Go with a simple GUI using Fyne. This application supports multiple hash functions (SHA1, SHA256, SHA512) and configurable digit lengths, making it compatible with standard TOTP implementations.

![Application UI](https://github.com/NilScript404/Totp-Generator/blob/main/UI.PNG)

## Features
- **Multiple Hash Functions:** Support for SHA1, SHA256, and SHA512
- **Configurable Digits:** Generate TOTPs with 6, 7, or 8 digits
- **Custom Secret Keys:** Input your own Base32 encoded secret keys
- **Real-time Updates:** TOTP updates every 30 seconds with a visual progress indicator
- **Simple GUI:** Clean and intuitive interface built with Fyne

## Technical Implementation
The generator follows RFC 6238 (TOTP) and RFC 4226 (HOTP) specifications, implementing:
- Base32 secret key decoding
- HMAC-based hash generation
- Dynamic time-based intervals
- Hash truncation to obtain final TOTP value

## Dependencies
- Go 1.x
- Fyne v2
- Standard Go crypto packages

## Installation
1. Install Go (if not already installed)
2. Install Fyne dependencies:
   ```bash
   go get fyne.io/fyne/v2
