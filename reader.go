// Copyright 2020 The Moov Authors
// Use of this source code is governed by an Apache License
// license that can be found in the LICENSE file.

package imagecashletter

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/gdamore/encoding"
)

// ParseError is returned for parsing reader errors.
// The first line is 1.
type ParseError struct {
	Line   int    // Line number where the error occurred
	Record string // Name of the record type being parsed
	Err    error  // The actual error
}

func (e *ParseError) Error() string {
	if e.Record == "" {
		return fmt.Sprintf("line:%d %T %s", e.Line, e.Err, e.Err)
	}
	return fmt.Sprintf("line:%d record:%s %T %s", e.Line, e.Record, e.Err, e.Err)
}

func (e *ParseError) Unwrap() error {
	return e.Err
}

// Reader reads records from a ACH-encoded file.
type Reader struct {
	// r handles the IO.Reader sent to be parser.
	scanner *bufio.Scanner
	// file is ach.file model being built as r is parsed.
	File File
	// func used to decode line to desired encoding ie. ASCII,EBCDIC
	decodeLine DecodeLineFn
	// line is the current line being parsed from the input r
	line string
	// currentCashLetter is the current CashLetter being parsed
	currentCashLetter CashLetter
	// line number of the file being parsed
	lineNum int
	// recordName holds the current record name being parsed.
	recordName string
}

// error creates a new ParseError based on err.
func (r *Reader) error(err error) error {
	return &ParseError{
		Line:   r.lineNum,
		Record: r.recordName,
		Err:    err,
	}
}

// addCurrentCashLetter creates the current cash letter for the file being read. A successful
// currentCashLetter will be added to r.File once parsed.
func (r *Reader) addCurrentCashLetter(cashLetter CashLetter) {
	r.currentCashLetter = cashLetter
}

// addCurrentBundle creates the CurrentBundle for the file being read. A successful
// currentBundle will be added to r.File once parsed.
func (r *Reader) addCurrentBundle(bundle *Bundle) {
	r.currentCashLetter.currentBundle = bundle
}

// addCurrentRoutingNumberSummary creates the CurrentRoutingNumberSummary for the file being read. A successful
// currentRoutingNumberSummary will be added to r.File once parsed.
func (r *Reader) addCurrentRoutingNumberSummary(rns *RoutingNumberSummary) {
	r.currentCashLetter.currentRoutingNumberSummary = rns
}

// NewReader returns a new ACH Reader that reads from r.
func NewReader(r io.Reader, opts ...ReaderOption) *Reader {
	f := NewFile()
	f.Control = FileControl{}
	reader := &Reader{
		File:       *f,
		scanner:    bufio.NewScanner(r),
		decodeLine: Passthrough,
	}
	for _, opt := range opts {
		opt(reader)
	}
	return reader
}

// DecodeLineFn is used to decode a scanned line into desired encoding.
// Depending on X9 spec, cashletter could be encoded as ASCII or EBCDIC
type DecodeLineFn func(lineIn string) (lineOut string, err error)

// Passthrough will return line as is
func Passthrough(lineIn string) (lineOut string, err error) {
	return lineIn, nil
}

// DecodeEBCDIC will decode a line from EBCDIC-0037 to UTF-8
func DecodeEBCDIC(lineIn string) (string, error) {
	lineOut, err := encoding.EBCDIC.NewDecoder().String(lineIn)
	if err != nil {
		return "", fmt.Errorf("error decoding '%X' as EBCDIC: %v\n", lineIn, err)
	}
	return lineOut, nil
}

// ReaderOption can be used to change default behavior of Reader
type ReaderOption func(*Reader)

// ReadVariableLineLengthOption allows Reader to split imagecashletter files based on encoded line lengths
func ReadVariableLineLengthOption() ReaderOption {
	scanVariableLengthLines := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		} else if len(data) < 4 && atEOF {
			// we ran out of bytes and we're at the end of the file
			return 0, nil, io.ErrUnexpectedEOF
		} else if len(data) < 4 {
			// we need at least the control bytes
			return 0, nil, nil
		}
		// line length can be variable
		// use the 4 control bytes at the beginning of a line to determine its length
		ctrl := data[0:4]
		dataLen := int(binary.BigEndian.Uint32(ctrl))
		lineLen := 4 + dataLen
		if lineLen <= len(data) {
			// return line while accounting for control bytes
			return lineLen, data[4:lineLen], nil
		} else if lineLen > len(data) && atEOF {
			// we need more data, but there is no more data to read
			return 0, nil, io.ErrUnexpectedEOF
		}
		// request more data.
		return 0, nil, nil
	}

	return func(r *Reader) {
		r.scanner.Split(scanVariableLengthLines)
	}
}

// ReadEbcdicEncodingOption allows Reader to decode scanned lines from EBCDIC to UTF-8
func ReadEbcdicEncodingOption() ReaderOption {
	return func(r *Reader) {
		r.decodeLine = DecodeEBCDIC
	}
}

// BufferSizeOption creates a byte slice of the specified size and uses it as the buffer
// for the Reader's internal scanner. You may need to set this when processing files that
// contain check details exceeding bufio.MaxScanTokenSize (64 kB).
func BufferSizeOption(size int) ReaderOption {
	return func(r *Reader) {
		r.scanner.Buffer(make([]byte, size), size)
	}
}

// Read reads each line of the imagecashletter file and defines which parser to use based
// on the first character of each line. It also enforces imagecashletter formatting rules and returns
// the appropriate error if issues are found.
func (r *Reader) Read() (File, []error) {
	r.lineNum = 0
	var errs []error // Accumulate errors

	// read through the entire file
	for r.scanner.Scan() {
		r.line = r.scanner.Text()
		r.lineNum++

		lineLength := len(r.line)

		if lineLength < 80 {
			msg := fmt.Sprintf(msgRecordLength, lineLength)
			err := &FileError{FieldName: "RecordLength", Value: strconv.Itoa(lineLength), Msg: msg}
			errs = append(errs, r.error(err)) // Accumulate the error
			continue                          // Continue to the next line
		}

		if err := r.parseLine(); err != nil {
			errs = append(errs, err) // Accumulate the error
			// Continue to the next line even if there's an error
			// in parsing a specific line
			continue
		}
	}

	if scanErr := r.scanner.Err(); scanErr != nil {
		err := &FileError{FieldName: "LineNumber", Value: strconv.Itoa(r.lineNum), Msg: scanErr.Error()}
		errs = append(errs, r.error(err)) // Accumulate the error
	}

	// File Header is mandatory so if it doesn't exist add error
	if (FileHeader{}) == r.File.Header {
		r.recordName = "FileHeader"
		err := &FileError{Msg: msgFileHeader}
		errs = append(errs, r.error(err)) // Accumulate the error
	}

	// File Control is not mandatory so we can skip the error
	// if (FileControl{}) == r.File.Control {
	// 	r.recordName = "FileControl"
	// 	err := &FileError{Msg: msgFileControl}
	// 	errs = append(errs, r.error(err)) // Accumulate the error
	// }

	// Add the current cash letter to the file if it exists
	if r.currentCashLetter.CashLetterHeader != nil {
		r.File.AddCashLetter(r.currentCashLetter)
	}

	return r.File, errs // Return the processed file and accumulated errors
}

func (r *Reader) parseLine() error { //nolint:gocyclo
	var err error
	switch r.line[:2] {
	case fileHeaderPos, fileHeaderEbcPos:
		err = r.parseFileHeader()
	case cashLetterHeaderPos, cashLetterHeaderEbcPos:
		err = r.parseCashLetterHeader()
	case bundleHeaderPos, bundleHeaderEbcPos:
		err = r.parseBundleHeader()
	case checkDetailPos, checkDetailEbcPos:
		err = r.parseCheckDetail()
	case checkDetailAddendumAPos, checkDetailAddendumAEbcPos:
		err = r.parseCheckDetailAddendumA()
	case checkDetailAddendumBPos, checkDetailAddendumBEbcPos:
		err = r.parseCheckDetailAddendumB()
	case checkDetailAddendumCPos, checkDetailAddendumCEbcPos:
		err = r.parseCheckDetailAddendumC()
	case imageViewDetailPos, imageViewDetailEbcPos:
		err = r.parseImageViewDetail()
	case imageViewDataPos, imageViewDataEbcPos:
		err = r.parseImageViewData()
	case imageViewAnalysisPos, imageViewAnalysisEbcPos:
		err = r.parseImageViewAnalysis()
	case returnDetailPos, returnDetailEbcPos:
		err = r.parseReturnDetail()
	case returnAddendumAPos, returnAddendumAPEbcos:
		err = r.parseReturnDetailAddendumA()
	case returnAddendumBPos, returnAddendumBEbcPos:
		err = r.parseReturnDetailAddendumB()
	case returnAddendumCPos, returnAddendumCEbcPos:
		err = r.parseReturnDetailAddendumC()
	case returnAddendumDPos, returnAddendumDEbcPos:
		err = r.parseReturnDetailAddendumD()
	case creditPos, creditEbcPos:
		err = r.parseCredit()
	case creditItemPos, creditItemEbcPos:
		err = r.parseCreditItem()
	case bundleControlPos, bundleControlEbcPos:
		err = r.parseBundleControl()
		if r.currentCashLetter.currentBundle == nil {
			r.error(&FileError{Msg: msgFileBundleControl})
		}
		// Add Bundle or ReturnBundle to CashLetter
		if r.currentCashLetter.currentBundle != nil {
			if err := r.currentCashLetter.currentBundle.Validate(); err != nil {
				r.recordName = "Bundles"
				r.error(err)
			}
			r.currentCashLetter.AddBundle(r.currentCashLetter.currentBundle)
			r.currentCashLetter.currentBundle = new(Bundle)
		}
	case routingNumberSummaryPos, routingNumberSummaryEbcPos:
		err = r.parseRoutingNumberSummary()
		if r.currentCashLetter.currentRoutingNumberSummary != nil {
			r.currentCashLetter.AddRoutingNumberSummary(r.currentCashLetter.currentRoutingNumberSummary)
			r.currentCashLetter.currentRoutingNumberSummary = new(RoutingNumberSummary)
		}
	case cashLetterControlPos, cashLetterControlEbcPos:
		// This is needed for validation od CashLetterControl since SettlementDate
		// is a conditional field and is only available for certain types of CashLetters.
		header := r.currentCashLetter.CashLetterHeader
		if header == nil {
			return errors.New("missing CashLetterHeader")
		}
		err = r.parseCashLetterControl()
		if err := r.currentCashLetter.Validate(); err != nil {
			r.recordName = "CashLetters"
			r.error(err)
		}
		r.File.AddCashLetter(r.currentCashLetter)
		r.currentCashLetter = CashLetter{}
	case fileControlPos, fileControlEbcPos:
		err = r.parseFileControl()
	default:
		msg := fmt.Sprintf(msgUnknownRecordType, r.line[:2])
		err = r.error(&FileError{FieldName: "recordType", Value: r.line[:2], Msg: msg})
	}
	return err
}

// parseFileHeader takes the input record string and parses the FileHeader values
func (r *Reader) parseFileHeader() error {
	r.recordName = "FileHeader"
	if (FileHeader{}) != r.File.Header {
		// There can only be one File Header per File
		r.error(&FileError{Msg: msgFileHeader})
	}
	lineOut, err := r.decodeLine(r.line)
	if err != nil {
		return err
	}
	fmt.Printf("Decoded line %d: %q\n", r.lineNum, lineOut)
	r.File.Header.Parse(lineOut)
	// Ensure valid FileHeader
	if err := r.File.Header.Validate(); err != nil {
		return r.error(err)
	}
	return nil
}

// parseCashLetterHeader takes the input record string and parses the CashLetterHeader values
func (r *Reader) parseCashLetterHeader() error {
	r.recordName = "CashLetterHeader"
	if r.currentCashLetter.CashLetterHeader != nil {
		// CashLetterHeader inside of current cash letter
		return r.error(&FileError{Msg: msgFileCashLetterInside})
	}
	lineOut, err := r.decodeLine(r.line)
	if err != nil {
		return err
	}
	fmt.Printf("Decoded line %d: %q\n", r.lineNum, lineOut)
	clh := NewCashLetterHeader()
	clh.Parse(lineOut)
	// Ensure we have a valid CashLetterHeader
	if err := clh.Validate(); err != nil {
		return r.error(err)
	}
	// Passing CashLetterHeader into NewCashLetter creates a CashLetter
	cl := NewCashLetter(clh)
	r.addCurrentCashLetter(cl)
	return nil
}

// parseBundleHeader takes the input record string and parses the BundleHeader values
func (r *Reader) parseBundleHeader() error {
	r.recordName = "BundleHeader"
	if r.currentCashLetter.currentBundle != nil {
		// BundleHeader inside of current Bundle
		if r.currentCashLetter.currentBundle.BundleHeader != nil {
			return r.error(&FileError{Msg: msgFileBundleInside})
		}
	}
	// Ensure we have a valid bundle header before building a bundle.
	lineOut, err := r.decodeLine(r.line)
	if err != nil {
		return err
	}
	fmt.Printf("Decoded line %d: %q\n", r.lineNum, lineOut)
	bh := NewBundleHeader()
	bh.Parse(lineOut)
	if err := bh.Validate(); err != nil {
		return r.error(err)
	}
	// Passing BundleHeader into NewBundle creates a Bundle
	bundle := NewBundle(bh)
	r.addCurrentBundle(bundle)
	return nil

}

// parseCheckDetail takes the input record string and parses the CheckDetail values
func (r *Reader) parseCheckDetail() error {
	r.recordName = "CheckDetail"
	if r.currentCashLetter.currentBundle == nil {
		return r.error(&FileError{Msg: msgFileBundleOutside})
	}
	lineOut, err := r.decodeLine(r.line)
	if err != nil {
		return err
	}
	fmt.Printf("Decoded line %d: %q\n", r.lineNum, lineOut)
	cd := new(CheckDetail)
	cd.Parse(lineOut)
	// Ensure valid CheckDetail
	if err := cd.Validate(); err != nil {
		return r.error(err)
	}
	// Add CheckDetail
	if r.currentCashLetter.currentBundle.BundleHeader != nil {
		r.currentCashLetter.currentBundle.AddCheckDetail(cd)
	}
	return nil
}

// parseCheckDetailAddendumA takes the input record string and parses the CheckDetailAddendumA values
func (r *Reader) parseCheckDetailAddendumA() error {
	r.recordName = "CheckDetailAddendumA"
	if r.currentCashLetter.currentBundle.GetChecks() == nil {
		msg := msgFileBundleOutside
		return r.error(&FileError{FieldName: "CheckDetailAddendumA", Msg: msg})
	}
	inputBytes := []byte(r.line)
	adjustedBytes := handleIBM1047Compatibility(inputBytes)
	lineOut, err := r.decodeLine(string(adjustedBytes))
	if err != nil {
		return err
	}

	cdAddendumA := NewCheckDetailAddendumA()
	cdAddendumA.Parse(lineOut)
	if err := cdAddendumA.Validate(); err != nil {
		return r.error(err)
	}
	entryIndex := len(r.currentCashLetter.currentBundle.GetChecks()) - 1
	// r.currentCashLetter.currentBundle.Checks[entryIndex].CheckDetailAddendumA = cdAddendumA
	r.currentCashLetter.currentBundle.Checks[entryIndex].AddCheckDetailAddendumA(cdAddendumA)
	return nil
}

func handleIBM1047Compatibility(input []byte) []byte {
	if !IsFRBCompatibilityModeEnabled() {
		return input
	}

	output := make([]byte, len(input))
	copy(output, input)

	// Replace bytes that map differently between IBM037 and IBM1047
	// but only for the ascii subset see https://en.wikibooks.org/wiki/Character_Encodings/Code_Tables/EBCDIC/EBCDIC_1047
	for i, b := range output {
		switch b {
		case 0xAD: // Ý -> [
			output[i] = 0xBA
		case 0xBD: // ¨ -> ]
			output[i] = 0xBB
		case 0x5F: // ¬ -> ^
			output[i] = 0xB0
		}
	}
	return output
}

// parseCheckDetailAddendumB takes the input record string and parses the CheckDetailAddendumB values
func (r *Reader) parseCheckDetailAddendumB() error {
	r.recordName = "CheckDetailAddendumB"
	if r.currentCashLetter.currentBundle.GetChecks() == nil {
		msg := msgFileBundleOutside
		return r.error(&FileError{FieldName: "CheckDetailAddendumB", Msg: msg})
	}
	lineOut, err := r.decodeLine(r.line)
	if err != nil {
		return err
	}
	fmt.Printf("Decoded line %d: %q\n", r.lineNum, lineOut)
	cdAddendumB := NewCheckDetailAddendumB()
	cdAddendumB.Parse(lineOut)
	if err := cdAddendumB.Validate(); err != nil {
		return r.error(err)
	}
	entryIndex := len(r.currentCashLetter.currentBundle.GetChecks()) - 1
	r.currentCashLetter.currentBundle.Checks[entryIndex].AddCheckDetailAddendumB(cdAddendumB)
	return nil
}

// parseCheckDetailAddendumC takes the input record string and parses the CheckDetailAddendumC values
func (r *Reader) parseCheckDetailAddendumC() error {
	r.recordName = "CheckDetailAddendumC"
	if r.currentCashLetter.currentBundle.GetChecks() == nil {
		msg := msgFileBundleOutside
		return r.error(&FileError{FieldName: "CheckDetailAddendumC", Msg: msg})
	}
	lineOut, err := r.decodeLine(r.line)
	if err != nil {
		return err
	}
	fmt.Printf("Decoded line %d: %q\n", r.lineNum, lineOut)
	cdAddendumC := NewCheckDetailAddendumC()
	cdAddendumC.Parse(lineOut)
	if err := cdAddendumC.Validate(); err != nil {
		return r.error(err)
	}
	entryIndex := len(r.currentCashLetter.currentBundle.GetChecks()) - 1
	r.currentCashLetter.currentBundle.Checks[entryIndex].AddCheckDetailAddendumC(cdAddendumC)
	return nil
}

// parseReturnDetail takes the input record string and parses the ReturnDetail values
func (r *Reader) parseReturnDetail() error {
	r.recordName = "ReturnDetail"
	if r.currentCashLetter.currentBundle == nil {
		return r.error(&FileError{Msg: msgFileBundleOutside})
	}
	lineOut, err := r.decodeLine(r.line)
	if err != nil {
		return err
	}
	fmt.Printf("Decoded line %d: %q\n", r.lineNum, lineOut)
	rd := new(ReturnDetail)
	rd.Parse(lineOut)
	if err := rd.Validate(); err != nil {
		return r.error(err)
	}
	if r.currentCashLetter.currentBundle.BundleHeader != nil {
		r.currentCashLetter.currentBundle.AddReturnDetail(rd)
	}
	return nil
}

// parseReturnDetailAddendumA takes the input record string and parses the ReturnDetailAddendumA values
func (r *Reader) parseReturnDetailAddendumA() error {
	r.recordName = "ReturnDetailAddendumA"
	if r.currentCashLetter.currentBundle.GetReturns() == nil {
		msg := msgFileBundleOutside
		return r.error(&FileError{FieldName: "ReturnDetailAddendumA", Msg: msg})
	}
	lineOut, err := r.decodeLine(r.line)
	if err != nil {
		return err
	}
	fmt.Printf("Decoded line %d: %q\n", r.lineNum, lineOut)
	rdAddendumA := NewReturnDetailAddendumA()
	rdAddendumA.Parse(lineOut)
	if err := rdAddendumA.Validate(); err != nil {
		return r.error(err)
	}
	entryIndex := len(r.currentCashLetter.currentBundle.GetReturns()) - 1
	// r.currentCashLetter.currentBundle.Returns[entryIndex].ReturnDetailAddendumA = rdAddendumA
	r.currentCashLetter.currentBundle.Returns[entryIndex].AddReturnDetailAddendumA(rdAddendumA)
	return nil
}

// parseReturnDetailAddendumB takes the input record string and parses the ReturnDetailAddendumB values
func (r *Reader) parseReturnDetailAddendumB() error {
	r.recordName = "ReturnDetailAddendumB"
	if r.currentCashLetter.currentBundle.GetReturns() == nil {
		msg := msgFileBundleOutside
		return r.error(&FileError{FieldName: "ReturnDetailAddendumB", Msg: msg})
	}
	lineOut, err := r.decodeLine(r.line)
	if err != nil {
		return err
	}
	fmt.Printf("Decoded line %d: %q\n", r.lineNum, lineOut)
	rdAddendumB := NewReturnDetailAddendumB()
	rdAddendumB.Parse(lineOut)
	if err := rdAddendumB.Validate(); err != nil {
		return r.error(err)
	}
	entryIndex := len(r.currentCashLetter.currentBundle.GetReturns()) - 1
	r.currentCashLetter.currentBundle.Returns[entryIndex].AddReturnDetailAddendumB(rdAddendumB)
	return nil
}

// parseReturnDetailAddendumC takes the input record string and parses the ReturnDetailAddendumC values
func (r *Reader) parseReturnDetailAddendumC() error {
	r.recordName = "ReturnDetailAddendumC"
	if r.currentCashLetter.currentBundle.GetReturns() == nil {
		msg := msgFileBundleOutside
		return r.error(&FileError{FieldName: "ReturnDetailAddendumC", Msg: msg})
	}
	lineOut, err := r.decodeLine(r.line)
	if err != nil {
		return err
	}
	fmt.Printf("Decoded line %d: %q\n", r.lineNum, lineOut)
	rdAddendumC := NewReturnDetailAddendumC()
	rdAddendumC.Parse(lineOut)
	if err := rdAddendumC.Validate(); err != nil {
		return r.error(err)
	}
	entryIndex := len(r.currentCashLetter.currentBundle.GetReturns()) - 1
	r.currentCashLetter.currentBundle.Returns[entryIndex].AddReturnDetailAddendumC(rdAddendumC)
	return nil
}

// parseReturnDetail*AddendumD takes the input record string and parses the ReturnDetail*AddendumD values
func (r *Reader) parseReturnDetailAddendumD() error {
	r.recordName = "ReturnDetailAddendumD"

	if r.currentCashLetter.currentBundle.GetReturns() == nil {
		msg := msgFileBundleOutside
		return r.error(&FileError{FieldName: "ReturnDetailAddendumD", Msg: msg})
	}
	lineOut, err := r.decodeLine(r.line)
	if err != nil {
		return err
	}
	fmt.Printf("Decoded line %d: %q\n", r.lineNum, lineOut)
	rdAddendumD := NewReturnDetailAddendumD()
	rdAddendumD.Parse(lineOut)
	if err := rdAddendumD.Validate(); err != nil {
		return r.error(err)
	}
	entryIndex := len(r.currentCashLetter.currentBundle.GetReturns()) - 1
	r.currentCashLetter.currentBundle.Returns[entryIndex].AddReturnDetailAddendumD(rdAddendumD)
	return nil
}

// parseImageViewDetail takes the input record string and parses the ImageViewDetail values
func (r *Reader) parseImageViewDetail() error {
	r.recordName = "ImageViewDetail"
	if r.currentCashLetter.currentBundle.GetChecks() != nil {
		lineOut, err := r.decodeLine(r.line)
		if err != nil {
			return err
		}
		fmt.Printf("Decoded line %d: %q\n", r.lineNum, lineOut)
		ivDetail := NewImageViewDetail()
		ivDetail.Parse(lineOut)
		if err := ivDetail.Validate(); err != nil {
			r.error(err)
			return nil // Return nil to continue processing
		}
		entryIndex := len(r.currentCashLetter.currentBundle.GetChecks()) - 1
		r.currentCashLetter.currentBundle.Checks[entryIndex].AddImageViewDetail(ivDetail)

	} else if r.currentCashLetter.currentBundle.GetReturns() != nil {
		lineOut, err := r.decodeLine(r.line)
		if err != nil {
			return err
		}
		fmt.Printf("Decoded line %d: %q\n", r.lineNum, lineOut)
		ivDetail := NewImageViewDetail()
		ivDetail.Parse(lineOut)
		if err := ivDetail.Validate(); err != nil {
			r.error(err)
			return nil // Return nil to continue processing
		}
		entryIndex := len(r.currentCashLetter.currentBundle.GetReturns()) - 1
		r.currentCashLetter.currentBundle.Returns[entryIndex].AddImageViewDetail(ivDetail)
	} else {
		msg := msgFileBundleOutside
		r.error(&FileError{FieldName: "ImageViewDetail", Msg: msg})
		return nil // Return nil to continue processing
	}

	return nil
}

// ImageViewDetail takes the input record string and parses ImageViewDetail for a check
func (r *Reader) ImageViewDetail() error {
	if r.currentCashLetter.currentBundle.GetChecks() != nil {
		lineOut, err := r.decodeLine(r.line)
		if err != nil {
			return err
		}
		fmt.Printf("Decoded line %d: %q\n", r.lineNum, lineOut)
		ivDetail := NewImageViewDetail()
		ivDetail.Parse(lineOut)
		if err := ivDetail.Validate(); err != nil {
			return r.error(err)
		}
		entryIndex := len(r.currentCashLetter.currentBundle.GetChecks()) - 1
		r.currentCashLetter.currentBundle.Checks[entryIndex].AddImageViewDetail(ivDetail)

	} else if r.currentCashLetter.currentBundle.GetReturns() != nil {
		lineOut, err := r.decodeLine(r.line)
		if err != nil {
			return err
		}
		fmt.Printf("Decoded line %d: %q\n", r.lineNum, lineOut)
		ivDetail := NewImageViewDetail()
		ivDetail.Parse(lineOut)
		if err := ivDetail.Validate(); err != nil {
			return r.error(err)
		}
		entryIndex := len(r.currentCashLetter.currentBundle.GetReturns()) - 1
		r.currentCashLetter.currentBundle.Returns[entryIndex].AddImageViewDetail(ivDetail)
	} else {
		msg := msgFileBundleOutside
		return r.error(&FileError{FieldName: "ImageViewDetail", Msg: msg})
	}

	return nil
}

// parseImageViewData takes the input record string and parses the ImageViewData values
func (r *Reader) parseImageViewData() error {
	r.recordName = "ImageViewData"
	if err := r.ImageViewData(); err != nil {
		return err
	}
	return nil
}

// ImageViewData takes the input record string and parses ImageViewData for a check
func (r *Reader) ImageViewData() error {
	if r.currentCashLetter.currentBundle.GetChecks() != nil {
		ivData := NewImageViewData()
		ivData.ParseAndDecode(r.line, r.decodeLine)
		if err := ivData.Validate(); err != nil {
			return r.error(err)
		}
		entryIndex := len(r.currentCashLetter.currentBundle.GetChecks()) - 1
		r.currentCashLetter.currentBundle.Checks[entryIndex].AddImageViewData(ivData)

	} else if r.currentCashLetter.currentBundle.GetReturns() != nil {
		ivData := NewImageViewData()
		ivData.ParseAndDecode(r.line, r.decodeLine)
		if err := ivData.Validate(); err != nil {
			return r.error(err)
		}
		entryIndex := len(r.currentCashLetter.currentBundle.GetReturns()) - 1
		r.currentCashLetter.currentBundle.Returns[entryIndex].AddImageViewData(ivData)
	} else {
		msg := msgFileBundleOutside
		return r.error(&FileError{FieldName: "ImageViewData", Msg: msg})
	}

	return nil
}

// parseImageViewAnalysis takes the input record string and parses ImageViewAnalysis values
func (r *Reader) parseImageViewAnalysis() error {
	r.recordName = "ImageViewAnalysis"
	if err := r.ImageViewAnalysis(); err != nil {
		return err
	}
	return nil
}

// ImageViewAnalysis takes the input record string and parses ImageViewAnalysis for a check
func (r *Reader) ImageViewAnalysis() error {
	if r.currentCashLetter.currentBundle.GetChecks() != nil {
		lineOut, err := r.decodeLine(r.line)
		if err != nil {
			return err
		}
		fmt.Printf("Decoded line %d: %q\n", r.lineNum, lineOut)
		ivAnalysis := NewImageViewAnalysis()
		ivAnalysis.Parse(lineOut)
		if err := ivAnalysis.Validate(); err != nil {
			return r.error(err)
		}
		entryIndex := len(r.currentCashLetter.currentBundle.GetChecks()) - 1
		r.currentCashLetter.currentBundle.Checks[entryIndex].AddImageViewAnalysis(ivAnalysis)

	} else if r.currentCashLetter.currentBundle.GetReturns() != nil {
		lineOut, err := r.decodeLine(r.line)
		if err != nil {
			return err
		}
		fmt.Printf("Decoded line %d: %q\n", r.lineNum, lineOut)
		ivAnalysis := NewImageViewAnalysis()
		ivAnalysis.Parse(lineOut)
		if err := ivAnalysis.Validate(); err != nil {
			return r.error(err)
		}
		entryIndex := len(r.currentCashLetter.currentBundle.GetReturns()) - 1
		r.currentCashLetter.currentBundle.Returns[entryIndex].AddImageViewAnalysis(ivAnalysis)
	} else {
		msg := msgFileBundleOutside
		return r.error(&FileError{FieldName: "ImageViewAnalysis", Msg: msg})
	}

	return nil
}

// parseCredit takes the input record string and parses the Credit values
func (r *Reader) parseCredit() error {
	// Current implementation has the credit letter outside the bundle but within the cash letter
	r.recordName = "Credit"
	if r.currentCashLetter.CashLetterHeader == nil {
		return r.error(&FileError{Msg: msgFileCredit})
	}
	lineOut, err := r.decodeLine(r.line)
	if err != nil {
		return err
	}
	fmt.Printf("Decoded line %d: %q\n", r.lineNum, lineOut)
	cr := new(Credit)
	cr.Parse(lineOut)
	if err := cr.Validate(); err != nil {
		return r.error(err)
	}
	r.currentCashLetter.AddCredit(cr)
	return nil
}

// parseCreditItem takes the input record string and parses the CreditItem values
func (r *Reader) parseCreditItem() error {
	// Current implementation has the credit letter outside the bundle but within the cash letter
	r.recordName = "CreditItem"
	if r.currentCashLetter.CashLetterHeader == nil {
		return r.error(&FileError{Msg: msgFileCreditItem})
	}
	lineOut, err := r.decodeLine(r.line)
	if err != nil {
		return err
	}
	fmt.Printf("Decoded line %d: %q\n", r.lineNum, lineOut)
	ci := new(CreditItem)
	ci.Parse(lineOut)
	if err := ci.Validate(); err != nil {
		return r.error(err)
	}
	r.currentCashLetter.AddCreditItem(ci)
	return nil
}

// parseBundleControl takes the input record string and parses the BundleControl values
func (r *Reader) parseBundleControl() error {
	r.recordName = "BundleControl"
	if r.currentCashLetter.currentBundle == nil || r.currentCashLetter.currentBundle.BundleControl == nil {
		return r.error(&FileError{Msg: msgFileBundleControl})
	}
	lineOut, err := r.decodeLine(r.line)
	if err != nil {
		return err
	}
	fmt.Printf("Decoded line %d: %q\n", r.lineNum, lineOut)
	r.currentCashLetter.currentBundle.GetControl().Parse(lineOut)
	if err := r.currentCashLetter.currentBundle.GetControl().Validate(); err != nil {
		r.error(err)
	}
	// Add Bundle or ReturnBundle to CashLetter
	if r.currentCashLetter.currentBundle != nil {
		if err := r.currentCashLetter.currentBundle.Validate(); err != nil {
			r.recordName = "Bundles"
			r.error(err)
		}
		r.currentCashLetter.AddBundle(r.currentCashLetter.currentBundle)
	}
	r.currentCashLetter.currentBundle = new(Bundle)
	return nil
}

// parseRoutingNumberSummary takes the input record string and parses the RoutingNumberSummary values
func (r *Reader) parseRoutingNumberSummary() error {
	r.recordName = "RoutingNumberSummary"
	if r.currentCashLetter.CashLetterHeader == nil {
		return r.error(&FileError{Msg: msgFileRoutingNumberSummary})
	}
	lineOut, err := r.decodeLine(r.line)
	if err != nil {
		return err
	}
	fmt.Printf("Decoded line %d: %q\n", r.lineNum, lineOut)
	rns := NewRoutingNumberSummary()
	rns.Parse(lineOut)
	if err := rns.Validate(); err != nil {
		return r.error(err)
	}
	return nil
}

// parseCashLetterControl takes the input record string and parses the CashLetterControl values
func (r *Reader) parseCashLetterControl() error {
	r.recordName = "CashLetterControl"
	if r.currentCashLetter.CashLetterHeader == nil {
		// CashLetterControl without a current CashLetter
		return r.error(&FileError{Msg: msgFileCashLetterControl})
	}
	lineOut, err := r.decodeLine(r.line)
	if err != nil {
		return err
	}
	fmt.Printf("Decoded line %d: %q\n", r.lineNum, lineOut)
	r.currentCashLetter.GetControl().Parse(lineOut)
	// Ensure valid CashLetterControl
	if err := r.currentCashLetter.GetControl().Validate(); err != nil {
		r.error(err)
	}
	r.File.AddCashLetter(r.currentCashLetter) // Add CashLetter to File
	r.currentCashLetter = CashLetter{}        // Reset currentCashLetter
	return nil
}

// parseFileControl takes the input record string and parses the FileControl values
func (r *Reader) parseFileControl() error {
	r.recordName = "FileControl"
	if (FileControl{}) != r.File.Control {
		// Can be only one file control per file
		return r.error(&FileError{Msg: msgFileControl})
	}
	lineOut, err := r.decodeLine(r.line)
	if err != nil {
		return err
	}
	fmt.Printf("Decoded line %d: %q\n", r.lineNum, lineOut)
	r.File.Control.Parse(lineOut)
	// Ensure valid FileControl
	if err := r.File.Control.Validate(); err != nil {
		return r.error(err)
	}
	return nil
}
