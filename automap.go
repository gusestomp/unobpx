package unobpx

import (
	"regexp"
	"strings"
)

// CommandRole identifies the semantic role of an OB command,
// independent of the binary label which rotates across PX tag versions.
type CommandRole = string

// Known OB command roles. These are stable across PX versions even
// though the command labels (binary strings) change with each tag rotation.
const (
	RoleSID         CommandRole = "sid"          // Session ID (single UUID)
	RoleVID         CommandRole = "vid"          // Visitor ID (UUID + TTL 31536000 + "false")
	RoleCTS         CommandRole = "cts"          // CTS token (UUID + "false"/"true")
	RoleCTSNum      CommandRole = "cts_num"      // CTS numeric token (18-22 digit number)
	RoleCS          CommandRole = "cs"           // Session hash (64-char hex)
	RoleTimestamp   CommandRole = "timestamp"    // Server timestamp (12-14 digit epoch ms)
	RoleCLS         CommandRole = "cls"          // Server CLS value (1-6 digit number)
	RoleToken       CommandRole = "token"        // Session token (15-25 char alphanumeric)
	RolePoW         CommandRole = "pow"          // Proof-of-work challenge (5 fields, field[4] is 64-char hex)
	RoleNonces      CommandRole = "nonces"       // Validation nonces (5 fields, long hex in [1] and [2])
	RoleCallback    CommandRole = "callback"     // Callback data (4+ fields, UUID in field[1])
	RoleCookie      CommandRole = "cookie"       // Set-Cookie instruction (_px* cookie data)
	RoleConfig      CommandRole = "config"       // Runtime config string (contains "bsco:")
	RoleCSMode      CommandRole = "cs_mode"      // Collector mode ("cu" = challenge, "cr" = clean)
	RoleSolveResult CommandRole = "solve_result" // Challenge result ("0" = accepted, "-1" = rejected)
)

// AutoMapCommands identifies OB command roles by analyzing value patterns.
//
// PX rotates command-type labels with each tag version, but the value
// formats remain stable. This function uses heuristic pattern matching
// to identify what each command does, regardless of its label.
//
// Returns a map of [CommandRole] -> command label string.
//
// Recognized patterns:
//   - UUID (8-4-4-4-12 hex): SID (1 field), VID (3 fields with TTL), CTS (2 fields)
//   - 64-char hex: session hash
//   - 18-22 digits: CTS numeric token
//   - 12-14 digits: server timestamp
//   - 1-6 digits: CLS value
//   - 15-25 char lowercase alphanumeric: session token
//   - Starts with "_px": Set-Cookie instruction
//   - "cu"/"cr": collector mode
//   - "0"/"-1": challenge result
func AutoMapCommands(decoded string) map[string]string {
	result := make(map[string]string)
	cmds := ParseCommands(decoded)

	uuidRe := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hexHash64Re := regexp.MustCompile(`^[0-9a-f]{64}$`)
	hexLongRe := regexp.MustCompile(`^[0-9a-f]{50,66}$`)
	digits20Re := regexp.MustCompile(`^\d{18,22}$`)
	digits13Re := regexp.MustCompile(`^\d{12,14}$`)
	digitsSmallRe := regexp.MustCompile(`^\d{1,6}$`)
	tokenRe := regexp.MustCompile(`^[a-z0-9]{15,25}$`)

	for cmdType, data := range cmds {
		if len(data) == 0 {
			continue
		}
		val := data[0]

		// Set-Cookie: first field starts with "_px"
		if len(data) >= 3 && strings.HasPrefix(val, "_px") {
			result[RoleCookie] = cmdType
			continue
		}

		// Cookie flags: 3 fields like ["cc", "60", value] — skip
		if len(data) == 3 && (val == "cc" || val == "rf" || val == "fp" || val == "tm") {
			continue
		}

		// UUID-based commands: disambiguate by field count
		if uuidRe.MatchString(val) {
			switch {
			case len(data) >= 3 && (data[1] == "31536000" || strings.Contains(data[1], "3153")):
				result[RoleVID] = cmdType
			case len(data) == 2 && (data[1] == "false" || data[1] == "true"):
				result[RoleCTS] = cmdType
			case len(data) == 1:
				result[RoleSID] = cmdType
			default:
				if _, ok := result[RoleSID]; !ok {
					result[RoleSID] = cmdType
				}
			}
			continue
		}

		// PoW challenge: 5 fields, field[4] is 64-char hex hash
		if len(data) >= 5 && hexHash64Re.MatchString(data[4]) {
			result[RolePoW] = cmdType
			continue
		}

		// Nonces: 5 fields, fields[1] and [2] are long hex
		if len(data) >= 5 && hexLongRe.MatchString(data[1]) && hexLongRe.MatchString(data[2]) {
			result[RoleNonces] = cmdType
			continue
		}

		// Callback: 4+ fields, field[1] is UUID
		if len(data) >= 4 && uuidRe.MatchString(data[1]) {
			result[RoleCallback] = cmdType
			continue
		}

		// 64-char hex hash: session hash
		if hexHash64Re.MatchString(val) {
			result[RoleCS] = cmdType
			continue
		}

		// 18-22 digit number: CTS numeric token
		if digits20Re.MatchString(val) {
			result[RoleCTSNum] = cmdType
			continue
		}

		// 12-14 digit number: timestamp
		if digits13Re.MatchString(val) {
			result[RoleTimestamp] = cmdType
			continue
		}

		// Challenge result: "0" or "-1"
		if len(data) == 1 && (val == "0" || val == "-1") {
			result[RoleSolveResult] = cmdType
			continue
		}

		// Small number: CLS
		if digitsSmallRe.MatchString(val) && len(data) == 1 {
			result[RoleCLS] = cmdType
			continue
		}

		// Session token: 15-25 char lowercase alphanumeric
		if len(data) == 1 && tokenRe.MatchString(val) {
			result[RoleToken] = cmdType
			continue
		}

		// Config string
		if len(data) == 1 && strings.Contains(val, "bsco:") {
			result[RoleConfig] = cmdType
			continue
		}

		// Collector mode: "cu" or "cr"
		if len(val) <= 3 && len(data) == 1 {
			result[RoleCSMode] = cmdType
			continue
		}
	}
	return result
}
