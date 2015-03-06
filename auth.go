package pwauth

// This will handle all aspects of authenticating users in our system
// For password managing/salting I used:
// http://austingwalters.com/building-a-web-server-in-go-salting-passwords/

import (
	"crypto/rand"
	"log"
	"strings"

	"code.google.com/p/go.crypto/bcrypt"
)

const (
	SaltLength = 64
	// On a scale of 3 - 31, how intense Bcrypt should be
	EncryptCost = 14
)

// This is returned when a new hash + salt combo is generated
type Password struct {
	hash string
	salt string
}

// this handles taking a raw user password and making in into something safe for
// storing in our DB
func hashPassword(saltedPassword string) string {

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(saltedPassword), EncryptCost)
	if err != nil {
		log.Fatal(err)
	}
	return string(hashedPassword)
}

// Handles merging together the salt and the password
func combine(salt string, rawPassword string) string {

	// concat salt + password
	pieces := []string{salt, rawPassword}
	saltedPassword := strings.Join(pieces, "")
	return saltedPassword
}

// Generates a random salt using DevNull
func generateSalt() string {

	// Read in data
	data := make([]byte, SaltLength)
	_, err := rand.Read(data)
	if err != nil {
		log.Fatal(err)
	}

	// Convert to a string
	salt := string(data[:])
	return salt
}

// Handles create a new hash/salt combo from a raw password as input
// by the user
func CreatePassword(rawPassword string) *Password {

	password := new(Password)
	password.salt = generateSalt()
	saltedPassword := combine(password.salt, rawPassword)
	password.hash = hashPassword(saltedPassword)

	return password
}

// Checks whether or not the correct password has been provided
func PasswordMatch(guess string, password *Password) bool {

	saltedGuess := combine(password.salt, guess)

	// compare to the real deal
	if bcrypt.CompareHashAndPassword([]byte(password.hash), []byte(saltedGuess)) != nil {
		return false
	}

	return true
}

func Unsalted(password string) string {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), EncryptCost)
	if err != nil {
		panic(err)
	}
	return string(hashedPassword)
}

// UnsaltedCompare compares an input password with its putative unsalted hash
// return true if equal, else false
func UnsaltedCompare(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return (err == nil)
}
