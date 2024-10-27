// minimal TOTP Generator based on SHA1 , SHA256 , SHA512
// every 30 seconds a new TOTP is generated
// user is capable of providing the SecretKey and the Encryption and total Digits by using the gui
// you can check the validity of the generated TOTP by using this website : https://piellardj.github.io/totp-generator

// reference
// TOTP introduction   https://en.wikipedia.org/wiki/Time-based_one-time_password
// TOTP reference      https://datatracker.ietf.org/doc/html/rfc6238
// HOTP reference      https://datatracker.ietf.org/doc/html/rfc4226
// Fyne Gui            https://docs.fyne.io/started/

package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"hash"
	"strconv"
	"time"
	
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// we have a secret key of type string , but based on the algorithm we need a []byte type
// this is the whole purpose of this function , to convert the string to a []byte
func DecodeBase32(secret string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(secret)
}

// generating the HMAC based on the secret key and the time , note that we need
// key and data to be of type []byte , based on the algorithm of rfc
func GenerateHMAC(hashFunc func() hash.Hash, key, data []byte) []byte {
	hmac := hmac.New(hashFunc, key)
	hmac.Write(data)
	
	// we perform the sum method in order to return a slice of bytes
	// because based on the RFC reference we need to manipulate the bytes later on.
	return hmac.Sum(nil)
}

// this function converts Unix time to a byte slice
func ConvertTime(interval int64) []byte {
	data := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		data[i] = byte(interval & 0xff)
		interval >>= 8
	}
	return data
}

// this is the tricky part , based on the RFC documentation we need to convert the hmac hash
// to a readable integer , and on top of that we only have to extract 6 or 7 or 8 digits
// from the converted integer

// HasTruncation truncates the hash to obtain a 31-bit integer.
func HashTruncation(hash []byte) int {
	// in this line of code , we find the offset and multiply it by 0x0f
	// because based on the documents offset has to be the low-order 4 bits of the last byte
	offset := hash[len(hash)-1] & 0x0f
	
	// now we need the truncated hash to be converted to an integer
	// from index offset to offset + 3 , there are 4 bytes
	// based on the docs we have to return a 31 bit integer
	// therefore we multiply the MSB of the biggest byte by 0x7f to avoid
	// any chances of overflow (0x7f is 01111111 in binary)
	// we multiply other indexes by 0xff (11111111 in binary) , to ensure that we are
	// only working with 8-bit Bytes
	// then we shift each Byte by 8 and convert each one to an integer , to form an integer
	// which we can extract our TOTP from.
	return ( 
	(int(hash[offset])&0x7f)<<24 |
	(int(hash[offset+1])&0xff)<<16 |
	(int(hash[offset+2])&0xff)<<8 |
	(int(hash[offset+3]) & 0xff))
}

// GenerateTOTP creates a TOTP using the provided secret, hash function, and number of digits.
func generateTOTP(secret string, hashFunc func() hash.Hash, digits int) (string, error) {
	// converting the secret key to a byte slice
	key, err := DecodeBase32(secret)
	if err != nil {
		return "", err
	}
	
	// calculating the current time interval
	// just the dynamic time which is increased by 1 every 30 second
	// this provides a dynamic variable which will also make the TOTP value dynamic
	// since we are dividing by 30 seconds , note that the value of interval will be
	// increased by 1 every 30 seconds , which is going to change the value of TOTP every 30 seconds
	interval := time.Now().Unix() / 30
	
	// converting the interval to a byte slice
	data := ConvertTime(interval)
	
	// generating the HMAC
	hash := GenerateHMAC(hashFunc, key, data)
	
	// truncate the hash to obtain a 31-bit integer
	truncatedHash := HashTruncation(hash)
	
	// calculating the TOTP value
	// if you want a 6 digit TOTP , divisor should be 1000000
	// if you want a 7 digit TOTP , divisor should be 10000000
	// you get the idea , this is why we write this loop
	divisor := 1
	for i := 0; i < digits; i++ {
		divisor *= 10
	}
	totp := truncatedHash % divisor
	
	// int to string conversion
	return strconv.Itoa(totp), nil
}

func main() {
	// default secret key and settings
	secret := "JBSWY3DPEHPK3PXP"
	hashFunc := sha1.New
	digits := 6
	
	// create a new Fyne application
	app := app.New()
	window := app.NewWindow("TOTP Generator")
	window.Resize(fyne.NewSize(300, 200))
	
	// UI components
	totpLabel := widget.NewLabel("")
	progress := widget.NewProgressBar()

	// dropdown for selecting the algorithm
	algorithmSelect := widget.NewSelect([]string{"SHA1", "SHA256", "SHA512"}, func(value string) {
		switch value {
		case "SHA1":
			hashFunc = sha1.New
		case "SHA256":
			hashFunc = sha256.New
		case "SHA512":
			hashFunc = sha512.New
		}
		updateTOTP(totpLabel, secret, hashFunc, digits)
	})
	// this is our default encryption , when the app starts the first TOTP is based on SHA1
	algorithmSelect.SetSelected("SHA1")

	// dropdown for selecting the number of digits
	// could have used an input box
	digitsSelect := widget.NewSelect([]string{"6", "7", "8"}, func(value string) {
		digits, _ = strconv.Atoi(value)
		updateTOTP(totpLabel, secret, hashFunc, digits)
	})
	//this is our default digits , when the app starts  the first TOTP will be 6 digits
	digitsSelect.SetSelected("6")

	// this is the input for secretkey , note that it has to be a valid base32 encoded string
	// otherwise TOTP wont be generated
	// base32 : https://en.wikipedia.org/wiki/Base32
	secretEntry := widget.NewEntry()
	secretEntry.SetPlaceHolder("Enter Secret Key")
	secretButton := widget.NewButton("Set Secret Key", func() {
		secret = secretEntry.Text
		updateTOTP(totpLabel, secret, hashFunc, digits)
	})
	// since this is a simple gui , we can just add our components to a container
	// fyne will take care of the positioning
	// othwerwise we would have to create custom containers and position the components manualy
	// container layout
	content := container.NewVBox(
		algorithmSelect,
		digitsSelect,
		secretEntry,
		secretButton,
		container.NewCenter(totpLabel),
		progress,
	)

	// set the content of the window
	window.SetContent(content)

	// generating the initial TOTP
	updateTOTP(totpLabel, secret, hashFunc, digits)
	
	// update TOTP and progress bar every 30 seconds
	// note that this has to a goroutine because we want it to be running seperately from the main thread
	go func() {
		for {
			for i := 0; i <= 30; i++ {
				progress.SetValue(float64(i) / 30.0)
				time.Sleep(1 * time.Second)
			}
			updateTOTP(totpLabel, secret, hashFunc, digits)
		}
	}()

	window.ShowAndRun()
}

// this function updates the TOTP label
func updateTOTP(label *widget.Label, secret string, hashFunc func() hash.Hash, digits int) {
	totp, err := generateTOTP(secret, hashFunc, digits)
	if err != nil {
		label.SetText("Error Generating TOTP")
	} else {
		label.SetText(totp)
	}
}
