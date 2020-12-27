package cmd

// import (
// 	"crypto/x509"
// 	"encoding/pem"
// 	"fmt"
// 	"io/ioutil"
// 	"os"

// 	"github.com/spf13/cobra"
// )

// // Features:
// //  - Unpack concatinated file into separate files (e.g. PEM bundle, certificate chain)
// //  - Pack separate files into concatinated file (e.g. PEM bundle)
// //  - Transcode format (e.g. DER to PEM or visa versa)
// //  - Unpack file (e.g. PFX to cert+key, or PEM blocks to seprate files)
// //  - Packing archive (e.g. cert+key to PFX, or seprate files into one PEM file as blocks)

// func newConvertCmd() *cobra.Command {
// 	convertCmd := &generateConvertCommand{}
// 	return convertCmd.GetCobraCommand()
// }

// type generateConvertCommand struct {
// 	InFile  []string
// 	OutFile []string
// }

// func (cnf *generateConvertCommand) GetCobraCommand() *cobra.Command {
// 	cobraCommand := &cobra.Command{
// 		Use:   "convert",
// 		Short: "Convert TLS related file formats",
// 		RunE:  cnf.Run,
// 	}

// 	flags := cobraCommand.Flags()
// 	flags.StringArrayVarP(&cnf.InFile, "in", "i", []string{}, "Input path to a file(s) to be converted")
// 	flags.StringArrayVarP(&cnf.OutFile, "out", "o", []string{}, "Output path for resulting file(s)")

// 	return cobraCommand
// }

// func (cnf *generateConvertCommand) Run(command *cobra.Command, args []string) error {
// 	if err := cnf.checkFlags(); err != nil {
// 		return err
// 	}

// 	if err := cnf.convert(); err != nil {
// 		return err
// 	}

// 	return nil
// }

// func (cnf *generateConvertCommand) checkFlags() error {
// 	if len(cnf.InFile) == 0 {
// 		return fmt.Errorf("Need at least one in file")
// 	}

// 	if len(cnf.OutFile) == 0 {
// 		return fmt.Errorf("Need at least one out file")
// 	}

// 	if len(cnf.InFile) > 1 && len(cnf.OutFile) > 1 {
// 		return fmt.Errorf("Either specify 1-to-1, many-to-1, or 1-to-many files")
// 	}

// 	return nil
// }

// func (cnf *generateConvertCommand) convert() error {
// 	if len(cnf.InFile) == 1 {
// 		if len(cnf.OutFile) == 1 {
// 			// 1-to-1
// 			if err := cnf.convertOneToOne(); err != nil {
// 				return fmt.Errorf("convertOneToOne: %w", err)
// 			}
// 			return nil
// 		}

// 		// 1-to-many
// 		if err := cnf.convertOneToMany(); err != nil {
// 			return fmt.Errorf("convertOneToMany: %w", err)
// 		}
// 		return nil
// 	}

// 	// many-to-1
// 	if err := cnf.convertManyToOne(); err != nil {
// 		return fmt.Errorf("convertManyToOne: %w", err)
// 	}
// 	return nil
// }

// func (cnf *generateConvertCommand) convertOneToOne() error {
// 	// Open the input file
// 	inFile, err := os.Open(cnf.InFile[0])
// 	if err != nil {
// 		return fmt.Errorf("os.Open: %w", err)
// 	}
// 	defer inFile.Close()

// 	// Read the contents of the file into memory, any crypto file should not large enough to cause issues
// 	inBytes, err := ioutil.ReadAll(inFile)
// 	if err != nil {
// 		return fmt.Errorf("io.Copy: %w", err)
// 	}

// 	inType := fileType(inBytes)

// 	return nil
// }

// func (cnf *generateConvertCommand) convertOneToMany() error {
// 	panic("not implemented")
// 	return nil
// }

// func (cnf *generateConvertCommand) convertManyToOne() error {
// 	panic("not implemented")
// 	return nil
// }

// func detectFileType(fileBytes []byte) fileType {
// 	pemBlock, _ := pem.Decode(fileBytes)
// 	if pemBlock != nil {
// 		return fileTypePEM
// 	}

// 	x509.ParsePKIXPublicKey
// }

// type fileType int

// const (
// 	fileTypeUnknown fileType = iota
// 	fileTypeDER
// 	fileTypePEM
// 	fileTypePKCS12
// )

// /*
// File formats:
//   - DER
//   - PEM
//   - PKCS12/P12/PFX

// Conversion types:
//   - 1 DER -> 1 PEM
//   - 1 PEM -> 1 DER
//   - chain DER -> chain PEM
//   - chain PEM -> chain DER
//   - DER/PEM cert + DER/PEM key -> PKCS12
// */
