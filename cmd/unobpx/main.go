// unobpx is a CLI tool for decoding PerimeterX (HUMAN Security) protocol data.
//
// Usage:
//
//	unobpx ob <base64_ob_string> <xor_key>
//	unobpx ob <base64_ob_string> --tag <tag_string>
//	unobpx sensor <encoded_payload> <uuid> <sts>
//	unobpx obs <wire_data>
//	unobpx xorkey <tag_string>
//	unobpx vm <init.js_file>
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/sardanioss/unobpx"
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
	case "vm":
		handleVM(os.Args[2:])
	case "devirt":
		handleDevirt(os.Args[2:])
	case "fieldmap":
		handleFieldMap(os.Args[2:])
	case "fieldassign":
		handleFieldAssign(os.Args[2:])
	case "fieldarith":
		handleFieldArithmetic(os.Args[2:])
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

func handleVM(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: unobpx vm <init.js_file>")
		os.Exit(1)
	}

	source, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	prog, err := unobpx.ParseInitJS(string(source))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Parse error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Parsed: f[%d], %d cases, root spec %d items, %d switch blocks\n",
		len(prog.F), len(prog.Cases), len(prog.Root), len(prog.Switches))
	for _, sw := range prog.Switches {
		fmt.Fprintf(os.Stderr, "  L%d: switch(k(%s)) halt=%d cases=%d\n",
			sw.Line, sw.ArrayVar, sw.HaltVal, len(sw.Cases))
	}

	// Expand initial n and show starting state
	n := unobpx.VMExpand(prog.F, prog.Root)
	fmt.Fprintf(os.Stderr, "Initial n[%d], opcode (sum) = %d\n\n", len(n), unobpx.VMSum(n))

	trace, err := unobpx.VMTrace(prog)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Trace error (after %d steps): %v\n", len(trace), err)
	}

	// Build switch summary
	type switchSummary struct {
		Line     int    `json:"line"`
		ArrayVar string `json:"array_var"`
		HaltVal  int    `json:"halt_val"`
		Cases    int    `json:"cases"`
	}
	var swSummary []switchSummary
	for _, sw := range prog.Switches {
		swSummary = append(swSummary, switchSummary{
			Line:     sw.Line,
			ArrayVar: sw.ArrayVar,
			HaltVal:  sw.HaltVal,
			Cases:    len(sw.Cases),
		})
	}

	// Output trace as JSON
	output := struct {
		FLen       int                 `json:"f_len"`
		CaseCount  int                 `json:"case_count"`
		Switches   []switchSummary     `json:"switches"`
		InitialN   []int               `json:"initial_n"`
		InitOpcode int                 `json:"init_opcode"`
		Steps      int                 `json:"steps"`
		Trace      []unobpx.TraceEntry `json:"trace"`
	}{
		FLen:       len(prog.F),
		CaseCount:  len(prog.Cases),
		Switches:   swSummary,
		InitialN:   n,
		InitOpcode: unobpx.VMSum(n),
		Steps:      len(trace),
		Trace:      trace,
	}

	pretty, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(pretty))
}

func handleDevirt(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: unobpx devirt <init.js_file> [switch_line|--all|--sub <name>]")
		fmt.Fprintln(os.Stderr, "  --all: devirtualize main interpreter + all sub-interpreters")
		fmt.Fprintln(os.Stderr, "  --sub <name>: devirtualize a specific sub-interpreter (e.g. l.R.b.s.e)")
		os.Exit(1)
	}

	source, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	// Check for flags
	allMode := false
	subName := ""
	outerSub := ""
	for i, a := range args[1:] {
		if a == "--all" {
			allMode = true
		}
		if a == "--sub" && i+2 < len(args) {
			subName = args[i+2]
		}
		if a == "--outer" && i+2 < len(args) {
			outerSub = args[i+2]
		}
	}

	prog, err := unobpx.ParseInitJS(string(source))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Parse error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Parsed: f[%d], %d switches\n", len(prog.F), len(prog.Switches))
	for _, sw := range prog.Switches {
		fmt.Fprintf(os.Stderr, "  L%d: switch(k(%s)) halt=%d cases=%d\n",
			sw.Line, sw.ArrayVar, sw.HaltVal, len(sw.Cases))
	}

	// Handle --outer: devirtualize a function defined in the outer switch (e.g. l.L.d, l.L.b)
	if outerSub != "" {
		// Find the outer switch (L1748, halt=216)
		var outerSw *unobpx.VMSwitch
		for i := range prog.Switches {
			if prog.Switches[i].HaltVal == 216 {
				outerSw = &prog.Switches[i]
				break
			}
		}
		if outerSw == nil {
			fmt.Fprintln(os.Stderr, "Could not find outer switch (halt=216)")
			os.Exit(1)
		}

		// Find the function definition spec in source
		// Match: l.L.d = function () { ... return b(u([spec]), ...
		// Use [^)]+ to grab everything inside u(...) that's not a closing paren
		specPattern := regexp.MustCompile(regexp.QuoteMeta(outerSub) + `\s*=\s*function\s*\(\)\s*\{[\s\S]*?return\s+b\(u\((\[[^)]+\])\)`)
		m := specPattern.FindStringSubmatch(string(source))
		if m == nil {
			fmt.Fprintf(os.Stderr, "Could not find spec for %s\n", outerSub)
			os.Exit(1)
		}
		spec := unobpx.ParseSpec(m[1])
		state := unobpx.VMExpand(prog.F, spec)
		fmt.Fprintf(os.Stderr, "\nDevirtualizing outer sub: %s\n", outerSub)
		fmt.Fprintf(os.Stderr, "Spec: %s\n", m[1])
		fmt.Fprintf(os.Stderr, "State[%d], opcode=%d, halt=%d\n\n", len(state), unobpx.VMSum(state), outerSw.HaltVal)

		// In the outer switch, n IS the state array, so pass state as outerN
		// for n[idx] resolution in case labels and decryptInline
		lines, devErr := unobpx.Devirtualize(outerSw, state, state, prog.F)
		if devErr != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", devErr)
		}
		for _, line := range lines {
			fmt.Println(line)
		}
		fmt.Fprintf(os.Stderr, "\nEmitted %d lines for %s\n", len(lines), outerSub)
		return
	}

	// Extract the sub-interpreter call chain.
	// l.Q.a is defined with its own bytecode spec (the inner n), and called with
	// an argument spec (which becomes l.R.a, the inner state array).
	defSpec, callSpec, found := unobpx.ExtractSubInterpreterSpecs(string(source))
	if !found {
		fmt.Fprintln(os.Stderr, "Could not find l.Q.a definition and call specs")
		os.Exit(1)
	}

	// The inner n is initialized from l.Q.a's definition spec
	innerN := unobpx.VMExpand(prog.F, defSpec)
	fmt.Fprintf(os.Stderr, "Inner n spec (from l.Q.a def): %d elements, initial opcode=%d\n",
		len(innerN), unobpx.VMSum(innerN))

	// The inner state (l.R.a) is initialized from the argument to l.Q.a
	innerState := unobpx.VMExpand(prog.F, callSpec)
	fmt.Fprintf(os.Stderr, "Inner state (l.R.a from l.Q.a call): %d elements, initial opcode=%d\n",
		len(innerState), unobpx.VMSum(innerState))

	// Trace the outer VM with the inner n to get the n state when the inner switch runs.
	// The second invocation of b() starts the outer switch (L1748) with innerN,
	// which runs through setup cases before entering the L1899 inner loop.
	innerTrace, finalN, err := unobpx.VMTraceWith(prog, innerN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Inner outer-trace: %d steps (err: %v)\n", len(innerTrace), err)
	} else {
		fmt.Fprintf(os.Stderr, "Inner outer-trace: %d steps, final n opcode=%d\n",
			len(innerTrace), unobpx.VMSum(finalN))
	}

	// Compute halt value: k(l.R.a) !== n[8] + 224
	haltVal := -1
	if len(finalN) > 8 {
		haltVal = finalN[8] + 224
		fmt.Fprintf(os.Stderr, "Halt value: n[8](%d) + 224 = %d\n", finalN[8], haltVal)
	}

	// Find the target switch
	targetLine := 0
	if len(args) >= 2 && args[1] != "--all" && args[1] != "--sub" {
		targetLine, err = strconv.Atoi(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid switch line: %s\n", args[1])
			os.Exit(1)
		}
	}

	// If no switch line specified, find the main interpreter (largest case count)
	var targetSw *unobpx.VMSwitch
	if targetLine == 0 {
		maxCases := 0
		for i := range prog.Switches {
			if len(prog.Switches[i].Cases) > maxCases {
				maxCases = len(prog.Switches[i].Cases)
				targetSw = &prog.Switches[i]
			}
		}
	} else {
		for i := range prog.Switches {
			if prog.Switches[i].Line == targetLine {
				targetSw = &prog.Switches[i]
				break
			}
		}
	}

	if targetSw == nil {
		fmt.Fprintln(os.Stderr, "Could not find target switch")
		os.Exit(1)
	}

	// Override halt value if we computed it
	if haltVal >= 0 {
		targetSw.HaltVal = haltVal
	}

	fmt.Fprintf(os.Stderr, "\nDevirtualizing L%d: switch(k(%s)) halt=%d, %d cases\n",
		targetSw.Line, targetSw.ArrayVar, targetSw.HaltVal, len(targetSw.Cases))

	// Copy innerState before Devirtualize mutates it
	initState := make([]int, len(innerState))
	copy(initState, innerState)
	outerN := finalN
	fmt.Fprintf(os.Stderr, "Initial inner state[%d], opcode=%d\n\n",
		len(initState), unobpx.VMSum(initState))

	// Decode the l.L.j string table using l.Q.a's n values (innerN).
	// When l.Q.a calls b(), the outer switch default case reinitializes l.L.j
	// with o("cipher", n[idx]) using l.Q.a's n values — NOT the root n values.
	// This is the l.L.j that the inner switch (l.R.b.s.b) actually reads.
	// Inner string table (l.R.b.s.b) — uses l.Q.a's n values + inner base-94 alphabet
	rawTable := unobpx.ExtractStringTableRaw(string(source), innerN)
	stringTable := unobpx.ExtractStringTable(string(source), innerN)
	fmt.Fprintf(os.Stderr, "Inner string table (l.R.b.s.b): %d entries\n", len(stringTable))
	for i := range stringTable {
		raw := ""
		if i < len(rawTable) {
			raw = rawTable[i]
		}
		decoded := stringTable[i]
		if raw != "" || decoded != "" {
			fmt.Fprintf(os.Stderr, "  [%d] raw=%q → decoded=%q\n", i, raw, decoded)
		}
	}

	// Outer string table (l.L.b) — uses l.L.b's n values + outer base-94 alphabet
	// l.L.b spec: extract from source
	llbSpec := regexp.MustCompile(`l\.L\.b\s*=\s*function\s*\(\)\s*\{[\s\S]*?return\s+b\(u\((\[[^)]+\])\)`)
	llbM := llbSpec.FindStringSubmatch(string(source))
	var outerTable []string
	if llbM != nil {
		llbN := unobpx.VMExpand(prog.F, unobpx.ParseSpec(llbM[1]))
		outerTable = unobpx.ExtractOuterStringTable(string(source), llbN)
		fmt.Fprintf(os.Stderr, "Outer string table (l.L.b): %d entries\n", len(outerTable))
		for i, s := range outerTable {
			if s != "" {
				fmt.Fprintf(os.Stderr, "  [%d] = %q\n", i, s)
			}
		}
	}

	// Extract all sub-interpreters
	subs := unobpx.ExtractAllSubInterpreters(string(source))
	fmt.Fprintf(os.Stderr, "Found %d sub-interpreters\n", len(subs))
	for _, sub := range subs {
		expanded := unobpx.VMExpand(prog.F, sub.Spec)
		fmt.Fprintf(os.Stderr, "  L%d %s: %d elements, opcode=%d\n",
			sub.Line, sub.Name, len(expanded), unobpx.VMSum(expanded))
	}
	fmt.Fprintln(os.Stderr)

	// If --sub specified, only devirtualize that sub-interpreter
	if subName != "" {
		for _, sub := range subs {
			if sub.Name == subName {
				subState := unobpx.VMExpand(prog.F, sub.Spec)
				fmt.Printf("// === Sub-interpreter: %s (L%d) ===\n", sub.Name, sub.Line)
				fmt.Printf("// Spec: [%s]\n", sub.SpecRaw)
				fmt.Printf("// State[%d], opcode=%d\n\n", len(subState), unobpx.VMSum(subState))

				subLines, subErr := unobpx.Devirtualize(targetSw, subState, outerN, prog.F)
				if subErr != nil {
					fmt.Fprintf(os.Stderr, "  Error: %v\n", subErr)
				}
				subLines = unobpx.ResolveConstantsInline(subLines, initState, outerN, prog.F)
				subLines = unobpx.ResolveStringTableInline(subLines, stringTable, outerTable, initState, outerN, prog.F)
				for _, line := range subLines {
					fmt.Println(line)
				}
				fmt.Fprintf(os.Stderr, "\nEmitted %d lines for %s\n", len(subLines), sub.Name)
				return
			}
		}
		fmt.Fprintf(os.Stderr, "Sub-interpreter %q not found\n", subName)
		os.Exit(1)
	}

	// Devirtualize main interpreter
	jsLines, err := unobpx.Devirtualize(targetSw, initState, outerN, prog.F)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Devirtualization error (after %d lines): %v\n", len(jsLines), err)
	}

	// Resolve l.R.a[N], n[N], f[N] constants, then inline string table lookups
	jsLines = unobpx.ResolveConstantsInline(jsLines, initState, outerN, prog.F)
	jsLines = unobpx.ResolveStringTableInline(jsLines, stringTable, outerTable, initState, outerN, prog.F)

	fmt.Println("// === Main interpreter ===")
	for _, line := range jsLines {
		fmt.Println(line)
	}
	fmt.Fprintf(os.Stderr, "\nEmitted %d lines for main interpreter\n", len(jsLines))

	// If --all, also devirtualize each sub-interpreter
	if allMode {
		for _, sub := range subs {
			subState := unobpx.VMExpand(prog.F, sub.Spec)
			fmt.Printf("\n// === Sub-interpreter: %s (L%d) ===\n", sub.Name, sub.Line)
			fmt.Printf("// Spec: [%s]\n", sub.SpecRaw)
			fmt.Printf("// State[%d], opcode=%d\n\n", len(subState), unobpx.VMSum(subState))

			subLines, subErr := unobpx.Devirtualize(targetSw, subState, outerN, prog.F)
			if subErr != nil {
				fmt.Fprintf(os.Stderr, "  %s error (after %d lines): %v\n", sub.Name, len(subLines), subErr)
			}
			subLines = unobpx.ResolveConstantsInline(subLines, initState, outerN, prog.F)
			subLines = unobpx.ResolveStringTableInline(subLines, stringTable, outerTable, initState, outerN, prog.F)
			for _, line := range subLines {
				fmt.Println(line)
			}
			fmt.Fprintf(os.Stderr, "  %s: %d lines\n", sub.Name, len(subLines))
		}
	}
}

func handleFieldMap(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: unobpx fieldmap <init.js_file> [--diff <other_init.js>]")
		os.Exit(1)
	}

	source, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	arrays := unobpx.ExtractFieldKeyArrays(string(source))
	directKeys := unobpx.ExtractDirectFieldKeys(string(source))

	// Summary to stderr
	totalKeys := 0
	for _, arr := range arrays {
		b64 := 0
		for _, item := range arr.Items {
			if unobpx.IsBase64SensorKey(item) {
				b64++
			}
		}
		totalKeys += b64
		fmt.Fprintf(os.Stderr, "  %s -> %s (offset %d): %d items, %d base64 keys\n",
			arr.LookupFn, arr.ArrayFn, arr.Offset, len(arr.Items), b64)
	}
	fmt.Fprintf(os.Stderr, "Total: %d arrays, %d base64 keys in arrays, %d direct keys\n",
		len(arrays), totalKeys, len(directKeys))

	// Check for --diff mode
	diffFile := ""
	for i, a := range args[1:] {
		if a == "--diff" && i+2 < len(args) {
			diffFile = args[i+2]
		}
	}

	if diffFile != "" {
		source2, err := os.ReadFile(diffFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading diff file: %v\n", err)
			os.Exit(1)
		}

		arrays2 := unobpx.ExtractFieldKeyArrays(string(source2))

		// Build key→(arrayFn, idx) maps
		map1 := make(map[string][2]interface{})
		for _, arr := range arrays {
			for i, item := range arr.Items {
				if unobpx.IsBase64SensorKey(item) {
					map1[item] = [2]interface{}{arr.ArrayFn, i}
				}
			}
		}
		map2 := make(map[string][2]interface{})
		for _, arr := range arrays2 {
			for i, item := range arr.Items {
				if unobpx.IsBase64SensorKey(item) {
					map2[item] = [2]interface{}{arr.ArrayFn, i}
				}
			}
		}

		// Count overlap
		shared := 0
		for k := range map1 {
			if _, ok := map2[k]; ok {
				shared++
			}
		}
		fmt.Fprintf(os.Stderr, "\nDiff: %d keys in file1, %d in file2, %d shared (same build = %v)\n",
			len(map1), len(map2), shared, shared == len(map1) && shared == len(map2))

		// JSON diff output
		type DiffOutput struct {
			File1Keys  int  `json:"file1_keys"`
			File2Keys  int  `json:"file2_keys"`
			SharedKeys int  `json:"shared_keys"`
			SameBuild  bool `json:"same_build"`
		}
		diffOut := DiffOutput{
			File1Keys:  len(map1),
			File2Keys:  len(map2),
			SharedKeys: shared,
			SameBuild:  shared == len(map1) && shared == len(map2),
		}
		pretty, _ := json.MarshalIndent(diffOut, "", "  ")
		fmt.Println(string(pretty))
		return
	}

	// Normal mode: JSON output of all arrays with their keys
	type ArrayOutput struct {
		ArrayFn    string   `json:"array_fn"`
		LookupFn   string   `json:"lookup_fn,omitempty"`
		Offset     int      `json:"offset"`
		TotalItems int      `json:"total_items"`
		Base64Keys []string `json:"base64_keys"`
	}

	var output []ArrayOutput
	for _, arr := range arrays {
		var b64Keys []string
		for _, item := range arr.Items {
			if unobpx.IsBase64SensorKey(item) {
				b64Keys = append(b64Keys, item)
			}
		}
		output = append(output, ArrayOutput{
			ArrayFn:    arr.ArrayFn,
			LookupFn:   arr.LookupFn,
			Offset:     arr.Offset,
			TotalItems: len(arr.Items),
			Base64Keys: b64Keys,
		})
	}

	// Add direct keys
	if len(directKeys) > 0 {
		output = append(output, ArrayOutput{
			ArrayFn:    "_direct",
			TotalItems: len(directKeys),
			Base64Keys: directKeys,
		})
	}

	pretty, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(pretty))
}

func handleFieldAssign(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: unobpx fieldassign <init.js_file> [--baseline <solve.py>] [--out <json_file>|--save] [--no-stdout]")
		os.Exit(1)
	}

	initPath := args[0]
	baselineFile := ""
	outFile := ""
	noStdout := false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--baseline":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Missing path after --baseline")
				os.Exit(1)
			}
			baselineFile = args[i+1]
			i++
		case "--out":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Missing path after --out")
				os.Exit(1)
			}
			outFile = args[i+1]
			i++
		case "--save":
			outFile = defaultFieldAssignOutputPath(initPath)
		case "--no-stdout":
			noStdout = true
		default:
			fmt.Fprintf(os.Stderr, "Unknown fieldassign option: %s\n", args[i])
			fmt.Fprintln(os.Stderr, "Usage: unobpx fieldassign <init.js_file> [--baseline <solve.py>] [--out <json_file>|--save] [--no-stdout]")
			os.Exit(1)
		}
	}

	source, err := os.ReadFile(initPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", initPath, err)
		os.Exit(1)
	}

	assignments := unobpx.ExtractFieldAssignments(string(source))
	fmt.Fprintf(os.Stderr, "Found %d sensor field assignments\n", len(assignments))

	// Count by type
	typeCounts := make(map[string]int)
	fnCounts := make(map[string]int)
	for _, a := range assignments {
		typeCounts[a.AssignType]++
		fnCounts[a.LookupFn]++
	}
	for t, c := range typeCounts {
		fmt.Fprintf(os.Stderr, "  %s: %d\n", t, c)
	}

	// Collect unique keys
	seen := make(map[string]bool)
	unique := 0
	for _, a := range assignments {
		if !seen[a.Key] {
			seen[a.Key] = true
			unique++
		}
	}
	fmt.Fprintf(os.Stderr, "Unique keys: %d\n", unique)

	// If --baseline, compare against solve.py baseline
	if baselineFile != "" {
		bSource, bErr := os.ReadFile(baselineFile)
		if bErr == nil {
			baselineKeys := extractBaselineKeys(string(bSource))
			src := string(source)
			fmt.Fprintf(os.Stderr, "\nBaseline keys: %d\n", len(baselineKeys))
			foundCount := 0
			var missingInArrayOnly []string
			var missingNotInSource []string
			var missingOther []string
			for _, bk := range baselineKeys {
				if seen[bk] {
					foundCount++
				} else if !strings.Contains(src, bk) {
					missingNotInSource = append(missingNotInSource, bk)
				} else {
					// Check if it only appears in array definitions (no direct assignment)
					missingInArrayOnly = append(missingInArrayOnly, bk)
				}
			}
			totalMissing := len(missingInArrayOnly) + len(missingNotInSource) + len(missingOther)
			fmt.Fprintf(os.Stderr, "Matched in fieldassign: %d\n", foundCount)
			fmt.Fprintf(os.Stderr, "Missing: %d\n", totalMissing)
			fmt.Fprintf(os.Stderr, "  In arrays only (dynamic iteration): %d\n", len(missingInArrayOnly))
			fmt.Fprintf(os.Stderr, "  Not in init.js (different build): %d\n", len(missingNotInSource))
			if len(missingNotInSource) > 0 {
				for _, k := range missingNotInSource {
					fmt.Fprintf(os.Stderr, "    %s\n", k)
				}
			}
		}
	}

	// Output JSON
	pretty, _ := json.MarshalIndent(assignments, "", "  ")
	if outFile != "" {
		if err := os.MkdirAll(filepath.Dir(outFile), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output directory for %s: %v\n", outFile, err)
			os.Exit(1)
		}
		if err := os.WriteFile(outFile, pretty, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", outFile, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Saved fieldassign JSON: %s\n", outFile)
	}
	if !noStdout {
		fmt.Println(string(pretty))
	}
}

func defaultFieldAssignOutputPath(initPath string) string {
	dir := filepath.Dir(initPath)
	base := filepath.Base(initPath)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	return filepath.Join(dir, stem+".fieldassign.json")
}

func handleFieldArithmetic(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: unobpx fieldarith <init.js_file>")
		os.Exit(1)
	}

	source, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", args[0], err)
		os.Exit(1)
	}

	findings := unobpx.AnalyzeArithmeticDecoderCalls(string(source))
	resolved := 0
	for _, finding := range findings {
		if finding.Confidence == "high" {
			resolved++
		}
	}
	fmt.Fprintf(os.Stderr, "Found %d arithmetic decoder calls\n", len(findings))
	fmt.Fprintf(os.Stderr, "Resolved: %d\n", resolved)

	pretty, _ := json.MarshalIndent(findings, "", "  ")
	fmt.Println(string(pretty))
}

// extractBaselineKeys pulls base64 sensor keys from a solve.py _SEQ1_BASELINE_D dict.
func extractBaselineKeys(source string) []string {
	re := regexp.MustCompile(`'([A-Za-z0-9+/]{11}=)'`)
	matches := re.FindAllStringSubmatch(source, -1)
	seen := make(map[string]bool)
	var keys []string
	for _, m := range matches {
		k := m[1]
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	return keys
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
	obs      Decrypt a Snare (snr.js) encrypted payload
	xorkey   Compute the OB XOR key from a PX tag string
	vm       Trace PX VM execution from an init.js file
	devirt   Devirtualize PX VM to equivalent JS source code
	fieldmap    Extract sensor field key arrays from init.js
	fieldassign Extract sensor field key→value assignments from init.js
	fieldarith  Analyze non-literal decoder calls inside field assignments

Examples:
# Decode OB response with known XOR key
unobpx ob "SGVsbG8gV29ybGQ=" 66

# Decode OB response using tag string to derive key
unobpx ob "SGVsbG8gV29ybGQ=" --tag "IUMUAGcoCHQlTA=="

# Decode sensor payload (needs uuid and sts from POST params)
unobpx sensor "<encoded>" "12345678-1234-..." "1771836032025"

# Decrypt Snare (snr.js) payload
unobpx obs "KAUHEVKF<base64_data>"

# Compute XOR key from any PX tag
unobpx xorkey "IUMUAGcoCHQlTA=="

# Trace PX VM execution from init.js
unobpx vm docs/px/walmart_4-3-26_init.js

# Extract field key arrays from init.js
unobpx fieldmap docs/px/walmart_4-3-26_init.js

# Analyze arithmetic decoder calls inside field assignments
unobpx fieldarith docs/px/walmart_4-9-26_init.js

# Diff field keys between two init.js versions
unobpx fieldmap docs/px/walmart_4-3-26_init.js --diff docs/px/walmart_4-4-26_init.js`)
}
