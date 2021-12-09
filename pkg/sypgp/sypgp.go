// Copyright (c) 2021 Apptainer a Series of LF Projects LLC
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2020, Control Command Inc. All rights reserved.
// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

// Package sypgp implements the openpgp integration into the apptainer project.
package sypgp

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/apptainer/apptainer/internal/pkg/util/fs"
	"github.com/apptainer/apptainer/internal/pkg/util/interactive"
	"github.com/apptainer/apptainer/pkg/syfs"
	"github.com/apptainer/apptainer/pkg/sylog"
)

var (
	errNotEncrypted = errors.New("key is not encrypted")

	// ErrEmptyKeyring is the error when the public, or private keyring
	// empty.
	ErrEmptyKeyring = errors.New("keyring is empty")
)

// KeyExistsError is a type representing an error associated to a specific key.
type KeyExistsError struct {
	fingerprint []byte
}

// HandleOpt is a type representing option which can be passed to NewHandle.
type HandleOpt func(*Handle)

// GlobalHandleOpt is the option to set a keyring as global.
func GlobalHandleOpt() HandleOpt {
	return func(h *Handle) {
		h.global = true
	}
}

// Handle is a structure representing a keyring
type Handle struct {
	path   string
	global bool
}

// GenKeyPairOptions parameters needed for generating new key pair.
type GenKeyPairOptions struct {
	Name      string
	Email     string
	Comment   string
	Password  string
	KeyLength int
}

func (e *KeyExistsError) Error() string {
	return fmt.Sprintf("the key with fingerprint %X already belongs to the keyring", e.fingerprint)
}

// dirPath returns a string describing the path to the sypgp home folder
func dirPath() string {
	sypgpDir := os.Getenv("APPTAINER_SYPGPDIR")
	if sypgpDir == "" {
		return filepath.Join(syfs.ConfigDir(), "sypgp")
	}
	return sypgpDir
}

// NewHandle initializes a new keyring in path.
func NewHandle(path string, opts ...HandleOpt) *Handle {
	newHandle := new(Handle)
	newHandle.path = path

	for _, opt := range opts {
		opt(newHandle)
	}

	if newHandle.path == "" {
		if newHandle.global {
			panic("global public keyring requires a path")
		}
		newHandle.path = dirPath()
	}

	return newHandle
}

// SecretPath returns a string describing the path to the private keys store
func (keyring *Handle) SecretPath() string {
	return filepath.Join(keyring.path, "pgp-secret")
}

// PublicPath returns a string describing the path to the public keys store
func (keyring *Handle) PublicPath() string {
	if keyring.global {
		return filepath.Join(keyring.path, "global-pgp-public")
	}
	return filepath.Join(keyring.path, "pgp-public")
}

// ensureDirPrivate makes sure that the file system mode for the named
// directory does not allow other users access to it (neither read nor
// write).
//
// TODO(mem): move this function to a common location
func ensureDirPrivate(dn string) error {
	mode := os.FileMode(0o700)

	oldumask := syscall.Umask(0o077)

	err := os.MkdirAll(dn, mode)

	// restore umask...
	syscall.Umask(oldumask)

	// ... and check if there was an error in the os.MkdirAll call
	if err != nil {
		return err
	}

	dirinfo, err := os.Stat(dn)
	if err != nil {
		return err
	}

	if currentMode := dirinfo.Mode(); currentMode != os.ModeDir|mode {
		sylog.Warningf("Directory mode (%o) on %s needs to be %o, fixing that...", currentMode & ^os.ModeDir, dn, mode)
		if err := os.Chmod(dn, mode); err != nil {
			return err
		}
	}

	return nil
}

// createOrAppendFile creates the named filename or open it in append mode,
// making sure it has the provided file permissions.
func createOrAppendFile(fn string, mode os.FileMode) (*os.File, error) {
	oldumask := syscall.Umask(0)
	defer syscall.Umask(oldumask)

	f, err := os.OpenFile(fn, os.O_APPEND|os.O_CREATE|os.O_WRONLY, mode)
	if err != nil {
		return nil, err
	}

	return f, f.Chmod(mode)
}

// createOrTruncateFile creates the named filename or truncate it,
// making sure it has the provided file permissions.
func createOrTruncateFile(fn string, mode os.FileMode) (*os.File, error) {
	oldumask := syscall.Umask(0)
	defer syscall.Umask(oldumask)

	f, err := os.OpenFile(fn, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, mode)
	if err != nil {
		return nil, err
	}

	return f, f.Chmod(mode)
}

// PathsCheck creates the sypgp home folder, secret and public keyring files
// for non global keyring.
func (keyring *Handle) PathsCheck() error {
	// global keyring is expected to have the parent directory created
	// and accessible by all users, it also doesn't use private keys, the
	// permission enforcement for the global keyring is deferred to
	// createOrAppendFile and createOrTruncateFile functions
	if keyring.global {
		return nil
	}

	if err := ensureDirPrivate(keyring.path); err != nil {
		return err
	}
	if err := fs.EnsureFileWithPermission(keyring.SecretPath(), 0o600); err != nil {
		return err
	}

	return fs.EnsureFileWithPermission(keyring.PublicPath(), 0o600)
}

func loadKeyring(fn string) (openpgp.EntityList, error) {
	f, err := os.Open(fn)
	if err != nil {
		if os.IsNotExist(err) {
			return openpgp.EntityList{}, nil
		}
		return nil, err
	}
	defer f.Close()

	return openpgp.ReadKeyRing(f)
}

// LoadPrivKeyring loads the private keys from local store into an EntityList
func (keyring *Handle) LoadPrivKeyring() (openpgp.EntityList, error) {
	if keyring.global {
		return nil, fmt.Errorf("global keyring doesn't contain private keys")
	}

	if err := keyring.PathsCheck(); err != nil {
		return nil, err
	}

	return loadKeyring(keyring.SecretPath())
}

// LoadPubKeyring loads the public keys from local store into an EntityList
func (keyring *Handle) LoadPubKeyring() (openpgp.EntityList, error) {
	if err := keyring.PathsCheck(); err != nil {
		return nil, err
	}

	return loadKeyring(keyring.PublicPath())
}

// loadKeysFromFile loads one or more keys from the specified file.
//
// The key can be either a public or private key, and the file might be
// in binary or ascii armored format.
func loadKeysFromFile(fn string) (openpgp.EntityList, error) {
	// use an intermediary bytes.Reader to support key import from
	// stdin for the seek operation below
	data, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewReader(data)

	if entities, err := openpgp.ReadKeyRing(buf); err == nil {
		return entities, nil
	}

	// cannot load keys from file, perhaps it's ascii armored?
	// rewind and try again
	if _, err := buf.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	return openpgp.ReadArmoredKeyRing(buf)
}

// printEntity pretty prints an entity entry to w
func printEntity(w io.Writer, index int, e *openpgp.Entity) {
	// TODO(mem): this should not be here, this is presentation
	for _, v := range e.Identities {
		fmt.Fprintf(w, "%d) U: %s (%s) <%s>\n", index, v.UserId.Name, v.UserId.Comment, v.UserId.Email)
	}
	fmt.Fprintf(w, "   C: %s\n", e.PrimaryKey.CreationTime)
	fmt.Fprintf(w, "   F: %0X\n", e.PrimaryKey.Fingerprint)
	bits, _ := e.PrimaryKey.BitLength()
	fmt.Fprintf(w, "   L: %d\n", bits)
}

func printEntities(w io.Writer, entities openpgp.EntityList) {
	for i, e := range entities {
		printEntity(w, i, e)
		fmt.Fprint(w, "   --------\n")
	}
}

// PrintPubKeyring prints the public keyring read from the public local store
func (keyring *Handle) PrintPubKeyring() error {
	pubEntlist, err := keyring.LoadPubKeyring()
	if err != nil {
		return err
	}

	printEntities(os.Stdout, pubEntlist)

	return nil
}

// PrintPrivKeyring prints the secret keyring read from the public local store
func (keyring *Handle) PrintPrivKeyring() error {
	privEntlist, err := keyring.LoadPrivKeyring()
	if err != nil {
		return err
	}

	printEntities(os.Stdout, privEntlist)

	return nil
}

// storePrivKeys writes all the private keys in list to the writer w.
func storePrivKeys(w io.Writer, list openpgp.EntityList) error {
	for _, e := range list {
		if err := e.SerializePrivateWithoutSigning(w, nil); err != nil {
			return err
		}
	}

	return nil
}

// appendPrivateKey appends a private key entity to the local keyring
func (keyring *Handle) appendPrivateKey(e *openpgp.Entity) error {
	if keyring.global {
		return fmt.Errorf("global keyring can't contain private keys")
	}

	f, err := createOrAppendFile(keyring.SecretPath(), 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	return storePrivKeys(f, openpgp.EntityList{e})
}

// storePubKeys writes all the public keys in list to the writer w.
func storePubKeys(w io.Writer, list openpgp.EntityList) error {
	for _, e := range list {
		if err := e.Serialize(w); err != nil {
			return err
		}
	}

	return nil
}

// appendPubKey appends a public key entity to the local keyring
func (keyring *Handle) appendPubKey(e *openpgp.Entity) error {
	mode := os.FileMode(0o600)
	if keyring.global {
		mode = os.FileMode(0o644)
	}

	f, err := createOrAppendFile(keyring.PublicPath(), mode)
	if err != nil {
		return err
	}
	defer f.Close()

	return storePubKeys(f, openpgp.EntityList{e})
}

// storePubKeyring overwrites the public keyring with the listed keys
func (keyring *Handle) storePubKeyring(keys openpgp.EntityList) error {
	mode := os.FileMode(0o600)
	if keyring.global {
		mode = os.FileMode(0o644)
	}

	f, err := createOrTruncateFile(keyring.PublicPath(), mode)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, k := range keys {
		if err := k.Serialize(f); err != nil {
			return fmt.Errorf("could not store public key: %s", err)
		}
	}

	return nil
}

// compareKeyEntity compares a key ID with a string, returning true if the
// key and oldToken match.
func compareKeyEntity(e *openpgp.Entity, oldToken string) bool {
	// TODO: there must be a better way to do this...
	return fmt.Sprintf("%X", e.PrimaryKey.Fingerprint) == oldToken
}

func findKeyByFingerprint(entities openpgp.EntityList, fingerprint string) *openpgp.Entity {
	// Strip any `0x` prefix off the front of the fingerprint we are looking for
	// to match with or without `0x` passed in
	fingerprint = strings.TrimPrefix(fingerprint, "0x")
	for _, e := range entities {
		if compareKeyEntity(e, fingerprint) {
			return e
		}
	}

	return nil
}

// CheckLocalPubKey will check if we have a local public key matching ckey string
// returns true if there's a match.
func (keyring *Handle) CheckLocalPubKey(ckey string) (bool, error) {
	// read all the local public keys
	elist, err := loadKeyring(keyring.PublicPath())
	switch {
	case os.IsNotExist(err):
		return false, nil

	case err != nil:
		return false, fmt.Errorf("unable to load local keyring: %v", err)
	}

	return findKeyByFingerprint(elist, ckey) != nil, nil
}

// removeKey removes one key identified by fingerprint from list.
//
// removeKey returns a new list with the key removed, or nil if the key
// was not found. The elements of the new list are the _same_ pointers
// found in the original list.
func removeKey(list openpgp.EntityList, fingerprint string) openpgp.EntityList {
	// Strip any `0x` prefix off the front of the fingerprint we are looking for
	// to match with or without `0x` passed in
	fingerprint = strings.TrimPrefix(fingerprint, "0x")
	for idx, e := range list {
		if compareKeyEntity(e, fingerprint) {
			newList := make(openpgp.EntityList, len(list)-1)
			copy(newList, list[:idx])
			copy(newList[idx:], list[idx+1:])
			return newList
		}
	}

	return nil
}

// RemovePubKey will delete a public key matching toDelete
func (keyring *Handle) RemovePubKey(toDelete string) error {
	// read all the local public keys
	elist, err := loadKeyring(keyring.PublicPath())
	switch {
	case os.IsNotExist(err):
		return nil

	case err != nil:
		return fmt.Errorf("unable to list local keyring: %v", err)
	}

	newKeyList := removeKey(elist, toDelete)
	if newKeyList == nil {
		return fmt.Errorf("no key matching given fingerprint found")
	}

	sylog.Verbosef("Updating local keyring: %v", keyring.PublicPath())

	return keyring.storePubKeyring(newKeyList)
}

func (keyring *Handle) genKeyPair(opts GenKeyPairOptions) (*openpgp.Entity, error) {
	conf := &packet.Config{RSABits: opts.KeyLength, DefaultHash: crypto.SHA384}

	entity, err := openpgp.NewEntity(opts.Name, opts.Comment, opts.Email, conf)
	if err != nil {
		return nil, err
	}

	if opts.Password != "" {
		// Encrypt private key
		if err = EncryptKey(entity, opts.Password); err != nil {
			return nil, err
		}
	}

	// Store key parts in local key caches
	if err = keyring.appendPrivateKey(entity); err != nil {
		return nil, err
	}

	if err = keyring.appendPubKey(entity); err != nil {
		return nil, err
	}

	return entity, nil
}

// GenKeyPair generates an PGP key pair and store them in the sypgp home folder
func (keyring *Handle) GenKeyPair(opts GenKeyPairOptions) (*openpgp.Entity, error) {
	if keyring.global {
		return nil, fmt.Errorf("operation not supported for global keyring")
	}

	if err := keyring.PathsCheck(); err != nil {
		return nil, err
	}

	entity, err := keyring.genKeyPair(opts)
	if err != nil {
		// Print the missing newline if there’s an error
		fmt.Printf("\n")
		return nil, err
	}

	return entity, nil
}

// EncryptKey encrypts a private key using a pass phrase
func EncryptKey(k *openpgp.Entity, pass string) error {
	if k.PrivateKey.Encrypted {
		return fmt.Errorf("key already encrypted")
	}
	return k.PrivateKey.Encrypt([]byte(pass))
}

// selectPubKey prints a public key list to user and returns the choice
func selectPubKey(el openpgp.EntityList) (*openpgp.Entity, error) {
	if len(el) == 0 {
		return nil, ErrEmptyKeyring
	}
	printEntities(os.Stdout, el)

	n, err := interactive.AskNumberInRange(0, len(el)-1, "Enter # of public key to use : ")
	if err != nil {
		return nil, err
	}

	return el[n], nil
}

// SelectPrivKey prints a secret key list to user and returns the choice
func SelectPrivKey(el openpgp.EntityList) (*openpgp.Entity, error) {
	if len(el) == 0 {
		return nil, ErrEmptyKeyring
	}
	printEntities(os.Stdout, el)

	n, err := interactive.AskNumberInRange(0, len(el)-1, "Enter # of private key to use : ")
	if err != nil {
		return nil, err
	}

	return el[n], nil
}

func serializeEntity(e *openpgp.Entity, blockType string) (string, error) {
	w := bytes.NewBuffer(nil)

	wr, err := armor.Encode(w, blockType, nil)
	if err != nil {
		return "", err
	}

	if err = e.Serialize(wr); err != nil {
		wr.Close()
		return "", err
	}
	wr.Close()

	return w.String(), nil
}

func serializePrivateEntity(e *openpgp.Entity, blockType string) (string, error) {
	w := bytes.NewBuffer(nil)

	wr, err := armor.Encode(w, blockType, nil)
	if err != nil {
		return "", err
	}

	if err = e.SerializePrivateWithoutSigning(wr, nil); err != nil {
		wr.Close()
		return "", err
	}
	wr.Close()

	return w.String(), nil
}

// RecryptKey Will decrypt a entity, then recrypt it with the same password.
// This function seems pritty usless, but its not!
func RecryptKey(k *openpgp.Entity, passphrase []byte) error {
	if !k.PrivateKey.Encrypted {
		return errNotEncrypted
	}

	if err := k.PrivateKey.Decrypt(passphrase); err != nil {
		return err
	}

	return k.PrivateKey.Encrypt(passphrase)
}

// ExportPrivateKey Will export a private key into a file (kpath).
func (keyring *Handle) ExportPrivateKey(kpath string, armor bool) error {
	if err := keyring.PathsCheck(); err != nil {
		return err
	}

	localEntityList, err := loadKeyring(keyring.SecretPath())
	if err != nil {
		return fmt.Errorf("unable to load private keyring: %v", err)
	}

	// Get a entity to export
	entityToExport, err := SelectPrivKey(localEntityList)
	if err != nil {
		return err
	}

	if entityToExport.PrivateKey.Encrypted {
		pass, err := interactive.AskQuestionNoEcho("Enter key passphrase : ")
		if err != nil {
			return err
		}
		err = RecryptKey(entityToExport, []byte(pass))
		if err != nil {
			return err
		}
	}

	// Create the file that we will be exporting to
	file, err := os.Create(kpath)
	if err != nil {
		return err
	}
	defer file.Close()

	if !armor {
		// Export the key to the file
		err = entityToExport.SerializePrivateWithoutSigning(file, nil)
	} else {
		var keyText string
		keyText, err = serializePrivateEntity(entityToExport, openpgp.PrivateKeyType)
		if err != nil {
			return fmt.Errorf("failed to read ASCII key format: %s", err)
		}
		file.WriteString(keyText)
	}

	if err != nil {
		return fmt.Errorf("unable to serialize private key: %v", err)
	}
	fmt.Printf("Private key with fingerprint %X correctly exported to file: %s\n", entityToExport.PrimaryKey.Fingerprint, kpath)

	return nil
}

// ExportPubKey Will export a public key into a file (kpath).
func (keyring *Handle) ExportPubKey(kpath string, armor bool) error {
	if err := keyring.PathsCheck(); err != nil {
		return err
	}

	localEntityList, err := loadKeyring(keyring.PublicPath())
	if err != nil {
		return fmt.Errorf("unable to open local keyring: %v", err)
	}

	entityToExport, err := selectPubKey(localEntityList)
	if err != nil {
		return err
	}

	file, err := os.Create(kpath)
	if err != nil {
		return fmt.Errorf("unable to create file: %v", err)
	}
	defer file.Close()

	if armor {
		var keyText string
		keyText, err = serializeEntity(entityToExport, openpgp.PublicKeyType)
		file.WriteString(keyText)
	} else {
		err = entityToExport.Serialize(file)
	}

	if err != nil {
		return fmt.Errorf("unable to serialize public key: %v", err)
	}
	fmt.Printf("Public key with fingerprint %X correctly exported to file: %s\n", entityToExport.PrimaryKey.Fingerprint, kpath)

	return nil
}

func findEntityByFingerprint(entities openpgp.EntityList, fingerprint []byte) *openpgp.Entity {
	for _, entity := range entities {
		if bytes.Equal(entity.PrimaryKey.Fingerprint, fingerprint) {
			return entity
		}
	}

	return nil
}

// importPrivateKey imports the specified openpgp Entity, which should
// represent a private key. The entity is added to the private keyring.
func (keyring *Handle) importPrivateKey(entity *openpgp.Entity, setNewPassword bool) error {
	if entity.PrivateKey == nil {
		return fmt.Errorf("corrupted key, unable to recover data")
	}

	// Load the local private keys as entitylist
	privateEntityList, err := keyring.LoadPrivKeyring()
	if err != nil {
		return err
	}

	if findEntityByFingerprint(privateEntityList, entity.PrimaryKey.Fingerprint) != nil {
		return &KeyExistsError{fingerprint: entity.PrivateKey.Fingerprint}
	}

	newEntity := *entity

	var password string
	if entity.PrivateKey.Encrypted {
		password, err = interactive.AskQuestionNoEcho("Enter your key password : ")
		if err != nil {
			return err
		}
		if err := newEntity.PrivateKey.Decrypt([]byte(password)); err != nil {
			return err
		}
	}

	if setNewPassword {
		// Get a new password for the key
		password, err = interactive.GetPassphrase("Enter a new password for this key : ", 3)
		if err != nil {
			return err
		}
	}

	if password != "" {
		if err := newEntity.PrivateKey.Encrypt([]byte(password)); err != nil {
			return err
		}
	}

	// Store the private key
	return keyring.appendPrivateKey(&newEntity)
}

// importPublicKey imports the specified openpgp Entity, which should
// represent a public key. The entity is added to the public keyring.
func (keyring *Handle) importPublicKey(entity *openpgp.Entity) error {
	// Load the local public keys as entitylist
	publicEntityList, err := keyring.LoadPubKeyring()
	if err != nil {
		return err
	}

	if findEntityByFingerprint(publicEntityList, entity.PrimaryKey.Fingerprint) != nil {
		return &KeyExistsError{fingerprint: entity.PrimaryKey.Fingerprint}
	}

	return keyring.appendPubKey(entity)
}

// ImportKey imports one or more keys from the specified file. The keys
// can be either a public or private keys, and the file can be either in
// binary or ascii-armored format.
func (keyring *Handle) ImportKey(kpath string, setNewPassword bool) error {
	// Load the private key as an entitylist
	pathEntityList, err := loadKeysFromFile(kpath)
	if err != nil {
		return fmt.Errorf("unable to get entity from: %s: %v", kpath, err)
	}

	for _, pathEntity := range pathEntityList {
		if pathEntity.PrivateKey != nil {
			// We have a private key
			err := keyring.importPrivateKey(pathEntity, setNewPassword)
			if err != nil {
				return err
			}

			fmt.Printf("Key with fingerprint %X successfully added to the private keyring\n",
				pathEntity.PrivateKey.Fingerprint)
		}

		// There's no else here because a single entity can have
		// both a private and public keys
		if pathEntity.PrimaryKey != nil {
			// We have a public key
			err := keyring.importPublicKey(pathEntity)
			if err != nil {
				return err
			}

			fmt.Printf("Key with fingerprint %X successfully added to the public keyring\n",
				pathEntity.PrimaryKey.Fingerprint)
		}
	}

	return nil
}
