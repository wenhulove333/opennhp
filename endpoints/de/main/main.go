package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/OpenNHP/opennhp/endpoints/de"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/version"
	ztdolib "github.com/OpenNHP/opennhp/nhp/core/ztdo"
	"github.com/urfave/cli/v2"
)

func main() {
	initApp()
}
func initApp() {
	app := cli.NewApp()
	app.Name = "nhp-device"
	app.Usage = "device entity for NHP protocol"
	app.Version = version.Version

	runCmd := &cli.Command{
		Name:  "run",
		Usage: "create and run device process for NHP protocol",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "mode", Value: "none", Usage: "encrypt;decrypt"},
			&cli.StringFlag{Name: "source", Value: "sample.txt", Usage: "source file"},
			&cli.StringFlag{Name: "policy", Value: "policyinfo.json", Usage: "The policy file contains the public key information of the data accessor"},
			&cli.StringFlag{Name: "output", Value: "output.txt", Usage: "Save path of the ztdo file"},
			&cli.StringFlag{Name: "meta", Value: "meta.json", Usage: "meta.json"},
			&cli.StringFlag{Name: "ztdo", Value: "", Usage: "path to the ztdo file"},
			&cli.StringFlag{Name: "decodeKey", Value: "", Usage: "decrypt key"},
			&cli.StringFlag{Name: "providerPublicKey", Value: "", Usage: "provider public key with base64 format"},
		},
		Action: func(c *cli.Context) error {
			mode := c.String("mode")
			source := c.String("source")
			policy := c.String("policy")
			output := c.String("output")
			ztdo := c.String("ztdo")
			decodeKey := c.String("decodeKey")
			meta := c.String("meta")
			providerPublicKeyBase64 := c.String("providerPublicKey")
			return runApp(mode, source, output, policy, ztdo, decodeKey, meta, providerPublicKeyBase64)
		},
	}

	keygenCmd := &cli.Command{
		Name:  "keygen",
		Usage: "generate key pairs for NHP devices",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "curve", Value: false, DisableDefaultText: true, Usage: "generate curve25519 keys"},
			&cli.BoolFlag{Name: "sm2", Value: false, DisableDefaultText: true, Usage: "generate sm2 keys"},
		},
		Action: func(c *cli.Context) error {
			var e core.Ecdh
			eccType := core.ECC_SM2
			if c.Bool("curve") {
				eccType = core.ECC_CURVE25519
			}
			e = core.NewECDH(eccType)
			pub := e.PublicKeyBase64()
			priv := e.PrivateKeyBase64()
			fmt.Println("Private key: ", priv)
			fmt.Println("Public key: ", pub)
			return nil
		},
	}

	pubkeyCmd := &cli.Command{
		Name:  "pubkey",
		Usage: "get public key from private key",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "curve", Value: false, DisableDefaultText: true, Usage: "get curve25519 key"},
			&cli.BoolFlag{Name: "sm2", Value: false, DisableDefaultText: true, Usage: "get sm2 key"},
		},
		Action: func(c *cli.Context) error {
			privKey, err := base64.StdEncoding.DecodeString(c.Args().First())
			if err != nil {
				return err
			}
			cipherType := core.ECC_SM2
			if c.Bool("curve") {
				cipherType = core.ECC_CURVE25519
			}
			e := core.ECDHFromKey(cipherType, privKey)
			if e == nil {
				return fmt.Errorf("invalid input key")
			}
			pub := e.PublicKeyBase64()
			fmt.Println("Public key: ", pub)
			return nil
		},
	}

	app.Commands = []*cli.Command{
		runCmd,
		keygenCmd,
		pubkeyCmd,
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

/*
*
decodeKey:Data Decryption Key
decodeSavePath:Save Directory Path
*/
func runApp(mode string, source string, output string, policy string, ztdoFilePath string, decodeKey string, meta string, providerPublicKeyBase64 string) error {
	exeFilePath, err := os.Executable()
	if err != nil {
		return err
	}
	exeDirPath := filepath.Dir(exeFilePath)
	a := &de.UdpDevice{}
	err = a.Start(exeDirPath, 4)
	if err != nil {
		return err
	}

	ztdo := ztdolib.NewZtdo()
	dataMsgPattern := [][]ztdolib.MessagePattern{
		{ztdolib.MessagePatternS, ztdolib.MessagePatternDHSS},
		{ztdolib.MessagePatternRS, ztdolib.MessagePatternDHSS},
	}

	if mode == "encrypt" {
		outputFilePath := output
		policyFile := policy
		dhpPolicy, err := de.ReadPolicyFile(policyFile)
		if err != nil {
			log.Error("failed to read policy file:%s\n", err)
			return err
		}

		ztdo.SetNhpServer(a.GetServerPeer().SendAddr().String())
		dataKeyPairEccMode := ztdolib.CURVE25519
		if a.GetCipherSchema() == 0 {
			dataKeyPairEccMode = ztdolib.SM2
		}

		dataPrk := ztdo.Generate(dataKeyPairEccMode)
		dataPrkBase64 := base64.StdEncoding.EncodeToString(dataPrk)
		//dataPrkBase64 := "sOAcQstGLq6qg6EezrgFlJu+0J61DU2t1TYgYDeS9XE="
		//dataPrk, _ := base64.StdEncoding.DecodeString(dataPrkBase64)
		dataPbk := core.ECDHFromKey(dataKeyPairEccMode.ToEccType(), dataPrk).PublicKey()
		sa := ztdolib.NewSymmetricAgreement(dataKeyPairEccMode, true)
		sa.SetMessagePatterns(dataMsgPattern)

		sa.SetStaticKeyPair(a.GetOwnEcdh())
		sa.SetRemoteStaticPublicKey(dataPbk)

		gcmKey, ad :=sa.AgreeSymmetricKey()

		symmetricCipherMode, err := ztdolib.NewSymmetricCipherMode(a.GetSymmetricCipherMode())
		if err != nil {
			log.Error("failed to create symmetric cipher mode:%s\n", err)
			return err
		}
		ztdo.SetCipherConfig(true, symmetricCipherMode, dataKeyPairEccMode)
		zoId := ztdo.GetObjectID()

		log.Info("Encrypt ztdo file(file name: %s and ztdo id: %s) with cipher settings: ECC mode(%s) and Symmetric Cipher Mode(%s)\n", source, zoId, dataKeyPairEccMode, symmetricCipherMode)

		if err := ztdo.EncryptZtdoFile(source, outputFilePath, gcmKey[:], ad); err != nil {
			log.Error("failed to encrypt ztdo file: %s\n", err)
			return err
		}

		a.SendDHPRegister(zoId, dhpPolicy, dataPrkBase64)

		os.Exit(0)
	} else if mode == "decrypt" {
		if err := ztdo.ParseHeader(ztdoFilePath); err != nil {
			log.Error("failed to parse ztdo header:%s\n", err)
			os.Exit(1)
		}

		dataKeyPairEccMode := ztdo.GetECCMode()

		dataPrk, _ := base64.StdEncoding.DecodeString(decodeKey)
		sa := ztdolib.NewSymmetricAgreement(dataKeyPairEccMode, false)
		sa.SetMessagePatterns(dataMsgPattern)
		sa.SetStaticKeyPair(core.ECDHFromKey(dataKeyPairEccMode.ToEccType(), dataPrk))

		providerPublicKey, _ := base64.StdEncoding.DecodeString(providerPublicKeyBase64)
		sa.SetRemoteStaticPublicKey(providerPublicKey)

		gcmKey, ad := sa.AgreeSymmetricKey()

		log.Info("Decrypting ztdo file(file name: %s and ztdo id: %s) with cipher settings: ECC mode(%s) and Symmetric Cipher Mode(%s)\n", ztdoFilePath, ztdo.GetObjectID(), dataKeyPairEccMode, ztdo.GetCipherMode())

		if err := ztdo.DecryptZtdoFile(ztdoFilePath, output, gcmKey[:], ad); err != nil {
			fmt.Printf("failed to decrypt ztdo file:%s\n", err)
			os.Exit(1)
		}

		os.Exit(0)
	}

	return nil
}
