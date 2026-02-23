// unobpx is a CLI tool for decoding PerimeterX (HUMAN Security) protocol data.
//
// Usage:
//
//	unobpx ob <base64_ob_string> <xor_key>
//	unobpx ob <base64_ob_string> --tag <tag_string>
//	unobpx sensor <encoded_payload> <uuid> <sts>
//	unobpx obs <wire_data>
//	unobpx xorkey <tag_string>
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/user/unobpx"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "ob":
		handleOB(os.Args[2:])
	case "sensor":
		handleSensor(os.Args[2:])
	case "obs":
		handleOBS(os.Args[2:])
	case "xorkey":
		handleXORKey(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func handleOB(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: unobpx ob <base64_ob_string> <xor_key|--tag tag_string>")
		os.Exit(1)
	}

	obData := args[0]
	var xorKey byte

	if args[1] == "--tag" {
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "Missing tag string after --tag")
			os.Exit(1)
		}
		xorKey = unobpx.ComputeOBXORKey(args[2])
		fmt.Fprintf(os.Stderr, "Computed XOR key from tag %q: %d\n\n", args[2], xorKey)
	} else {
		k, err := strconv.Atoi(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid XOR key %q: %v\n", args[1], err)
			os.Exit(1)
		}
		xorKey = byte(k)
	}

	decoded := unobpx.DecodeOB(obData, xorKey)
	if decoded == "" {
		fmt.Fprintln(os.Stderr, "Failed to decode OB data")
		os.Exit(1)
	}

	// Parse and display commands
	cmds := unobpx.ParseCommands(decoded)
	roles := unobpx.AutoMapCommands(decoded)

	// Build reverse map: label -> role
	labelToRole := make(map[string]string)
	for role, label := range roles {
		labelToRole[label] = role
	}

	fmt.Printf("Decoded OB: %d bytes, %d commands\n\n", len(decoded), len(cmds))

	for label, fields := range cmds {
		role := labelToRole[label]
		if role == "" {
			role = "?"
		}
		fmt.Printf("  [%s] %-12s %s\n", label, "("+role+")", formatFields(fields))
	}

	// Extract cookies
	cookies := unobpx.ExtractCookies(decoded)
	if len(cookies) > 0 {
		fmt.Printf("\nCookies:\n")
		for name, value := range cookies {
			display := value
			if len(display) > 60 {
				display = display[:60] + "..."
			}
			fmt.Printf("  %s = %s\n", name, display)
		}
	}

	fmt.Printf("\nRaw decoded:\n%s\n", decoded)
}

func handleSensor(args []string) {
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: unobpx sensor <encoded_payload> <uuid> <sts>")
		os.Exit(1)
	}

	decoded, err := unobpx.DecodeSensor(args[0], args[1], args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Decode error: %v\n", err)
		os.Exit(1)
	}

	// Pretty-print if valid JSON
	var obj any
	if json.Unmarshal([]byte(decoded), &obj) == nil {
		pretty, _ := json.MarshalIndent(obj, "", "  ")
		fmt.Println(string(pretty))
	} else {
		fmt.Println(decoded)
	}
}

func handleOBS(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: unobpx obs <wire_data>")
		os.Exit(1)
	}

	decrypted, err := unobpx.DecryptOBS(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Decrypt error: %v\n", err)
		os.Exit(1)
	}

	// Pretty-print if valid JSON
	var obj any
	if json.Unmarshal([]byte(decrypted), &obj) == nil {
		pretty, _ := json.MarshalIndent(obj, "", "  ")
		fmt.Println(string(pretty))
	} else {
		fmt.Println(decrypted)
	}
}

func handleXORKey(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: unobpx xorkey <tag_string>")
		os.Exit(1)
	}
	key := unobpx.ComputeOBXORKey(args[0])
	fmt.Printf("Tag:     %s\n", args[0])
	fmt.Printf("XOR Key: %d (0x%02x)\n", key, key)
}

func formatFields(fields []string) string {
	if len(fields) == 0 {
		return "(empty)"
	}
	parts := make([]string, len(fields))
	for i, f := range fields {
		if len(f) > 50 {
			parts[i] = f[:50] + "..."
		} else {
			parts[i] = f
		}
	}
	return strings.Join(parts, " | ")
}

func printUsage() {
	fmt.Println(`unobpx - PerimeterX (HUMAN Security) Protocol Decoder

Usage:
  unobpx <command> [arguments]

Commands:
  ob       Decode an OB collector response
  sensor   Decode a sensor payload from network traffic
  obs      Decrypt an OBS (Observer/SNR) encrypted payload
  xorkey   Compute the OB XOR key from a PX tag string

Examples:
  # Decode OB response with known XOR key
  unobpx ob "SGVsbG8gV29ybGQ=" 66

  # Decode OB response using tag string to derive key
  unobpx ob "SGVsbG8gV29ybGQ=" --tag "IUMUAGcoCHQlTA=="

  # Decode sensor payload (needs uuid and sts from POST params)
  unobpx sensor "<encoded>" "12345678-1234-..." "1771836032025"

  # Decrypt OBS payload
  unobpx obs "KAUHEVKF<base64_data>"

  # Compute XOR key from any PX tag
  unobpx xorkey "IUMUAGcoCHQlTA=="`)
}
