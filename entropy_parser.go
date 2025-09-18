package main

import (
	"fmt"
	"strconv"
	"strings"
)

// EntropyType represents the detected format of entropy input
type EntropyType int

const (
	EntropyTypeUnknown EntropyType = iota
	EntropyTypeDice
	EntropyTypeCards
	EntropyTypeRaw
)

// ParsedEntropy contains the parsed entropy data
type ParsedEntropy struct {
	Type       EntropyType
	RawInput   string
	ParsedData []byte
	BitCount   int
}

// parseEntropy attempts to parse the entropy string into an efficient binary format
func parseEntropy(input string, forceRaw bool) (*ParsedEntropy, error) {
	result := &ParsedEntropy{
		RawInput: input,
	}

	// If raw mode is forced, just use the input as-is
	if forceRaw {
		result.Type = EntropyTypeRaw
		result.ParsedData = []byte(input)
		result.BitCount = len(result.ParsedData) * 8
		return result, nil
	}

	// Try to detect and parse the format
	input = strings.TrimSpace(input)
	
	// Try dice format first (space-separated numbers)
	if data, bitCount, err := parseDiceFormat(input); err == nil {
		result.Type = EntropyTypeDice
		result.ParsedData = data
		result.BitCount = bitCount
		return result, nil
	}

	// Try card format (space-separated card notation)
	if data, bitCount, err := parseCardFormat(input); err == nil {
		result.Type = EntropyTypeCards
		result.ParsedData = data
		result.BitCount = bitCount
		return result, nil
	}

	// Format not recognized
	return nil, fmt.Errorf("entropy format not recognized. Use -raw flag to bypass format detection")
}

// parseDiceFormat parses space-separated d20 dice rolls
// Returns packed binary representation using 5 bits per die (since 20 < 2^5)
func parseDiceFormat(input string) ([]byte, int, error) {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return nil, 0, fmt.Errorf("empty input")
	}

	// Validate all parts are valid d20 values (1-20)
	dice := make([]uint8, len(parts))
	for i, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil || num < 1 || num > 20 {
			return nil, 0, fmt.Errorf("invalid dice value: %s (must be 1-20)", part)
		}
		dice[i] = uint8(num - 1) // Store as 0-19 for efficiency
	}

	// Pack dice into bytes using 5 bits per die
	bitCount := len(dice) * 5
	byteCount := (bitCount + 7) / 8
	packed := make([]byte, byteCount)
	
	bitPos := 0
	for _, die := range dice {
		// Pack 5 bits for each die
		byteIdx := bitPos / 8
		bitOffset := bitPos % 8
		
		if bitOffset <= 3 {
			// Die fits in current byte
			packed[byteIdx] |= die << (3 - bitOffset)
		} else {
			// Die spans two bytes
			packed[byteIdx] |= die >> (bitOffset - 3)
			if byteIdx+1 < len(packed) {
				packed[byteIdx+1] |= die << (11 - bitOffset)
			}
		}
		
		bitPos += 5
	}

	return packed, bitCount, nil
}

// parseCardFormat parses space-separated card notation (e.g., "As 4d Jh")
// Returns packed binary using 6 bits per card (52 cards < 2^6)
func parseCardFormat(input string) ([]byte, int, error) {
	parts := strings.Fields(input)
	if len(parts) != 52 {
		return nil, 0, fmt.Errorf("card format requires exactly 52 cards, got %d", len(parts))
	}

	// Define card mappings
	rankMap := map[byte]uint8{
		'A': 0, '2': 1, '3': 2, '4': 3, '5': 4, '6': 5, '7': 6,
		'8': 7, '9': 8, 'T': 9, 'J': 10, 'Q': 11, 'K': 12,
	}
	suitMap := map[byte]uint8{
		's': 0, 'd': 1, 'h': 2, 'c': 3,
	}

	// Validate and convert cards
	cards := make([]uint8, 52)
	seenCards := make(map[uint8]bool)
	
	for i, card := range parts {
		if len(card) != 2 {
			return nil, 0, fmt.Errorf("invalid card format: %s", card)
		}
		
		rank, rankOk := rankMap[card[0]]
		suit, suitOk := suitMap[card[1]]
		
		if !rankOk || !suitOk {
			return nil, 0, fmt.Errorf("invalid card: %s", card)
		}
		
		// Card value: rank * 4 + suit (0-51)
		cardValue := rank*4 + suit
		
		// Check for duplicates
		if seenCards[cardValue] {
			return nil, 0, fmt.Errorf("duplicate card: %s", card)
		}
		seenCards[cardValue] = true
		
		cards[i] = cardValue
	}

	// Pack cards into bytes using 6 bits per card
	bitCount := 52 * 6 // 312 bits total
	byteCount := (bitCount + 7) / 8 // 39 bytes
	packed := make([]byte, byteCount)
	
	bitPos := 0
	for _, card := range cards {
		// Pack 6 bits for each card
		byteIdx := bitPos / 8
		bitOffset := bitPos % 8
		
		if bitOffset <= 2 {
			// Card fits in current byte
			packed[byteIdx] |= card << (2 - bitOffset)
		} else {
			// Card spans two bytes
			packed[byteIdx] |= card >> (bitOffset - 2)
			if byteIdx+1 < len(packed) {
				packed[byteIdx+1] |= card << (10 - bitOffset)
			}
		}
		
		bitPos += 6
	}

	return packed, bitCount, nil
}

// debugPrintParsedEntropy prints debug information about parsed entropy
func debugPrintParsedEntropy(pe *ParsedEntropy) {
	fmt.Println("DEBUG: === Entropy Parsing Results ===")
	
	switch pe.Type {
	case EntropyTypeDice:
		fmt.Println("DEBUG: Format detected: D20 dice rolls")
		fmt.Printf("DEBUG: Theoretical entropy: %.1f bits per die × dice count\n", 4.32)
	case EntropyTypeCards:
		fmt.Println("DEBUG: Format detected: Card shuffle")
		fmt.Printf("DEBUG: Theoretical entropy: %.1f bits (log₂(52!))\n", 225.58)
	case EntropyTypeRaw:
		fmt.Println("DEBUG: Format: Raw bytes (no parsing)")
	default:
		fmt.Println("DEBUG: Format: Unknown")
	}
	
	fmt.Printf("DEBUG: Input length: %d characters\n", len(pe.RawInput))
	fmt.Printf("DEBUG: Packed length: %d bytes\n", len(pe.ParsedData))
	fmt.Printf("DEBUG: Actual bits used: %d\n", pe.BitCount)
	fmt.Printf("DEBUG: Efficiency: %.1f%% (%d bits / %d bytes)\n", 
		float64(pe.BitCount)*100/float64(len(pe.ParsedData)*8), 
		pe.BitCount, len(pe.ParsedData))
	fmt.Printf("DEBUG: Packed data (hex): %x\n", pe.ParsedData)
	
	// Show first few unpacked values for verification
	if pe.Type == EntropyTypeDice {
		fmt.Print("DEBUG: First few dice values: ")
		for i := 0; i < 5 && i*5 < pe.BitCount; i++ {
			bitPos := i * 5
			byteIdx := bitPos / 8
			bitOffset := bitPos % 8
			
			var die uint8
			if bitOffset <= 3 {
				die = (pe.ParsedData[byteIdx] >> (3 - bitOffset)) & 0x1F
			} else {
				die = ((pe.ParsedData[byteIdx] << (bitOffset - 3)) & 0x1F)
				if byteIdx+1 < len(pe.ParsedData) {
					die |= pe.ParsedData[byteIdx+1] >> (11 - bitOffset)
				}
			}
			fmt.Printf("%d ", die+1)
		}
		fmt.Println("...")
	}
}