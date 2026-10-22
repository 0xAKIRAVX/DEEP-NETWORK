package main

import (
	"fmt"
	"strings"
)

// ─────────── pure-Go QR encoder (byte mode, v1..15, ECC M/L — ported from the Python panel) ───────────

type qrEC struct {
	ec, b1, d1, b2, d2 int
}

var qrECTable = map[string][]qrEC{
	"M": {
		{10, 1, 16, 0, 0}, {16, 1, 28, 0, 0}, {26, 1, 44, 0, 0}, {18, 2, 32, 0, 0}, {24, 2, 43, 0, 0},
		{16, 4, 27, 0, 0}, {18, 4, 31, 0, 0}, {22, 2, 38, 2, 39}, {22, 3, 36, 2, 37}, {26, 4, 43, 1, 44},
		{30, 1, 50, 4, 51}, {22, 6, 36, 2, 37}, {22, 8, 37, 1, 38}, {24, 4, 40, 5, 41}, {24, 5, 41, 5, 42},
	},
	"L": {
		{7, 1, 19, 0, 0}, {10, 1, 34, 0, 0}, {15, 1, 55, 0, 0}, {20, 1, 80, 0, 0}, {26, 1, 108, 0, 0},
		{18, 2, 68, 0, 0}, {20, 2, 78, 0, 0}, {24, 2, 97, 0, 0}, {30, 2, 116, 0, 0}, {18, 2, 68, 2, 69},
		{20, 4, 81, 0, 0}, {24, 2, 92, 2, 93}, {26, 4, 107, 0, 0}, {30, 3, 115, 1, 116}, {22, 5, 87, 1, 88},
	},
}

var qrAlign = [][]int{
	{}, {6, 18}, {6, 22}, {6, 26}, {6, 30}, {6, 34}, {6, 22, 38}, {6, 24, 42}, {6, 26, 46},
	{6, 28, 50}, {6, 30, 54}, {6, 32, 58}, {6, 34, 62}, {6, 26, 46, 66}, {6, 26, 48, 70},
}

var qrFmtLevel = map[string]int{"M": 0, "L": 1}

func gfMul(a, b int) int {
	r := 0
	for b > 0 {
		if b&1 == 1 {
			r ^= a
		}
		b >>= 1
		a <<= 1
		if a&0x100 != 0 {
			a ^= 0x11D
		}
	}
	return r
}

func gfPow(a, n int) int {
	r := 1
	for i := 0; i < n; i++ {
		r = gfMul(r, a)
	}
	return r
}

func rsEC(data []byte, n int) []byte {
	gen := []int{1}
	for i := 0; i < n; i++ {
		nxt := make([]int, len(gen)+1)
		for j, c := range gen {
			nxt[j] ^= c
			nxt[j+1] ^= gfMul(c, gfPow(2, i))
		}
		gen = nxt
	}
	rem := make([]int, len(data)+n)
	copy(rem, b2i(data))
	for i := 0; i < len(data); i++ {
		f := rem[i]
		if f != 0 {
			for j := 0; j < len(gen); j++ {
				rem[i+j] ^= gfMul(gen[j], f)
			}
		}
	}
	return i2b(rem[len(data):])
}

func b2i(b []byte) []int {
	out := make([]int, len(b))
	for i, v := range b {
		out[i] = int(v)
	}
	return out
}

func i2b(v []int) []byte {
	out := make([]byte, len(v))
	for i, x := range v {
		out[i] = byte(x)
	}
	return out
}

func qrBitCapacity(v int, level string) int {
	t := qrECTable[level][v-1]
	codewords := t.b1*t.d1 + t.b2*t.d2
	bits := codewords*8 - 4
	if v >= 10 {
		bits -= 8
	}
	return bits / 8
}

type qrEncoded struct {
	v     int
	level string
	cws   []byte
}

func qrEncode(data string) (*qrEncoded, error) {
	raw := []byte(data)
	level := "M"
	if qrBitCapacity(15, "M") < len(raw) && qrBitCapacity(15, "L") >= len(raw) {
		level = "L"
	}
	v := 0
	for i := 1; i <= 15; i++ {
		if qrBitCapacity(i, level) >= len(raw) {
			v = i
			break
		}
	}
	if v == 0 {
		return nil, fmt.Errorf("data too long for QR")
	}
	nbits := 4 + len(raw)*8
	if v >= 10 {
		nbits += 16
	} else {
		nbits += 8
	}
	var sb strings.Builder
	sb.WriteString("0100")
	if v >= 10 {
		sb.WriteString(fmt.Sprintf("%016b", len(raw)))
	} else {
		sb.WriteString(fmt.Sprintf("%08b", len(raw)))
	}
	for _, by := range raw {
		sb.WriteString(fmt.Sprintf("%08b", by))
	}
	t := qrECTable[level][v-1]
	cap := (t.b1*t.d1 + t.b2*t.d2) * 8
	term := 4
	if cap-nbits < term {
		term = cap - nbits
	}
	if term > 0 {
		sb.WriteString(strings.Repeat("0", term))
	}
	stream := sb.String()
	if pad := (8 - len(stream)%8) % 8; pad > 0 {
		stream += strings.Repeat("0", pad)
	}
	var cws []int
	for i := 0; i+8 <= len(stream); i += 8 {
		v := 0
		for j := 0; j < 8; j++ {
			v = v<<1 | int(stream[i+j]-'0')
		}
		cws = append(cws, v)
	}
	target := t.b1*t.d1 + t.b2*t.d2
	pads := []int{0xEC, 0x11}
	for pi := 0; len(cws) < target; pi++ {
		cws = append(cws, pads[pi%2])
	}
	var blocks [][]int
	idx := 0
	for _, g := range [][2]int{{t.b1, t.d1}, {t.b2, t.d2}} {
		for k := 0; k < g[0]; k++ {
			blocks = append(blocks, cws[idx:idx+g[1]])
			idx += g[1]
		}
	}
	ecws := make([][]int, len(blocks))
	for i, b := range blocks {
		ecws[i] = b2i(rsEC(i2b(b), t.ec))
	}
	maxd := 0
	for _, b := range blocks {
		if len(b) > maxd {
			maxd = len(b)
		}
	}
	var out []byte
	for i := 0; i < maxd; i++ {
		for _, b := range blocks {
			if i < len(b) {
				out = append(out, byte(b[i]))
			}
		}
	}
	for i := 0; i < t.ec; i++ {
		for _, e := range ecws {
			out = append(out, byte(e[i]))
		}
	}
	return &qrEncoded{v, level, out}, nil
}

func qrMatrix(v int, level string, cws []byte) [][]bool {
	size := 17 + 4*v
	m := make([][]int8, size)
	for i := range m {
		m[i] = make([]int8, size) // 0 empty, 1 dark, 2 light
	}
	set := func(r, c int, val bool) {
		if r >= 0 && r < size && c >= 0 && c < size {
			if val {
				m[r][c] = 1
			} else {
				m[r][c] = 2
			}
		}
	}
	finder := func(r, c int) {
		for dr := -1; dr <= 7; dr++ {
			for dc := -1; dc <= 7; dc++ {
				rr, cc := r+dr, c+dc
				if rr < 0 || rr >= size || cc < 0 || cc >= size {
					continue
				}
				if dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6 {
					dark := dr == 0 || dr == 6 || dc == 0 || dc == 6 || (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4)
					set(rr, cc, dark)
				} else {
					set(rr, cc, false)
				}
			}
		}
	}
	finder(0, 0)
	finder(0, size-7)
	finder(size-7, 0)
	centers := qrAlign[v-1]
	for _, r := range centers {
		for _, c := range centers {
			if m[r][c] != 0 {
				continue
			}
			for dr := -2; dr <= 2; dr++ {
				for dc := -2; dc <= 2; dc++ {
					ring := absI(dr)
					if absI(dc) > ring {
						ring = absI(dc)
					}
					set(r+dr, c+dc, ring != 1)
				}
			}
		}
	}
	for i := 8; i < size-8; i++ {
		set(6, i, i%2 == 0)
		set(i, 6, i%2 == 0)
	}
	set(size-8, 8, true)
	var fmtCells [][2]int
	for i := 0; i < 9; i++ {
		if i != 6 {
			fmtCells = append(fmtCells, [2]int{8, i}, [2]int{i, 8})
		}
	}
	for i := 0; i < 8; i++ {
		fmtCells = append(fmtCells, [2]int{8, size - 1 - i})
	}
	for i := 0; i < 8; i++ {
		fmtCells = append(fmtCells, [2]int{size - 1 - i, 8})
	}
	for _, rc := range fmtCells {
		if m[rc[0]][rc[1]] == 0 {
			m[rc[0]][rc[1]] = 2
		}
	}
	if v >= 7 {
		for i := 0; i < 6; i++ {
			for j := 0; j < 3; j++ {
				set(i, size-11+j, false)
			}
		}
		for j := 0; j < 6; j++ {
			for i := 0; i < 3; i++ {
				set(size-11+i, j, false)
			}
		}
	}
	bits := ""
	for _, b := range cws {
		bits += fmt.Sprintf("%08b", b)
	}
	var dataCells [][2]int
	for r := 0; r < size; r++ {
		for c := 0; c < size; c++ {
			if m[r][c] == 0 {
				dataCells = append(dataCells, [2]int{r, c})
			}
		}
	}
	bitI := 0
	col := size - 1
	upward := true
	for col > 0 {
		if col == 6 {
			col--
		}
		var rows []int
		if upward {
			for r := size - 1; r >= 0; r-- {
				rows = append(rows, r)
			}
		} else {
			for r := 0; r < size; r++ {
				rows = append(rows, r)
			}
		}
		for _, r := range rows {
			for _, c := range []int{col, col - 1} {
				if m[r][c] == 0 {
					if bitI < len(bits) {
						set(r, c, bits[bitI] == '1')
						bitI++
					} else {
						set(r, c, false)
					}
				}
			}
		}
		upward = !upward
		col -= 2
	}
	maskOK := func(mask, r, c int) bool {
		switch mask {
		case 0:
			return (r+c)%2 == 0
		case 1:
			return r%2 == 0
		case 2:
			return c%3 == 0
		case 3:
			return (r+c)%3 == 0
		case 4:
			return (r/2+c/3)%2 == 0
		case 5:
			return (r*c)%2+(r*c)%3 == 0
		case 6:
			return ((r*c)%2+(r*c)%3)%2 == 0
		default:
			return ((r+c)%2+(r*c)%3)%2 == 0
		}
	}
	penalty := func(mat [][]bool) int {
		p := 0
		rowsAll := [][]bool{}
		for _, row := range mat {
			rowsAll = append(rowsAll, row)
		}
		for c := 0; c < size; c++ {
			colL := make([]bool, size)
			for r := 0; r < size; r++ {
				colL[r] = mat[r][c]
			}
			rowsAll = append(rowsAll, colL)
		}
		for _, row := range rowsAll {
			run, prev := 1, -1
			for _, cell := range row {
				bi := 0
				if cell {
					bi = 1
				}
				if bi == prev {
					run++
					if run == 5 {
						p += 3
					} else if run > 5 {
						p++
					}
				} else {
					run, prev = 1, bi
				}
			}
		}
		for r := 0; r < size-1; r++ {
			for c := 0; c < size-1; c++ {
				if mat[r][c] == mat[r][c+1] && mat[r][c] == mat[r+1][c] && mat[r][c] == mat[r+1][c+1] {
					p += 3
				}
			}
		}
		pat1 := []bool{true, false, true, true, true, false, true}
		for _, row := range rowsAll {
			for i := 0; i+7 <= len(row); i++ {
				match := true
				for k := 0; k < 7; k++ {
					if row[i+k] != pat1[k] {
						match = false
						break
					}
				}
				if match {
					if i >= 4 && !anyTrue(row[i-4:i]) {
						p += 40
					}
					if i+11 <= len(row) && !anyTrue(row[i+7:i+11]) {
						p += 40
					}
				}
			}
		}
		dark := 0
		for _, row := range mat {
			for _, cell := range row {
				if cell {
					dark++
				}
			}
		}
		p += absI(dark*100-50*size*size) / (5 * size * size) * 10
		return p
	}
	var best [][]bool
	bestScore := -1
	bestMask := 0
	for mask := 0; mask < 8; mask++ {
		mat := make([][]bool, size)
		for r := 0; r < size; r++ {
			mat[r] = make([]bool, size)
			for c := 0; c < size; c++ {
				mat[r][c] = m[r][c] == 1
			}
		}
		for _, rc := range dataCells {
			if maskOK(mask, rc[0], rc[1]) {
				mat[rc[0]][rc[1]] = !mat[rc[0]][rc[1]]
			}
		}
		sc := penalty(mat)
		if bestScore < 0 || sc < bestScore {
			best, bestScore, bestMask = mat, sc, mask
		}
	}
	fdata := qrFmtLevel[level]<<3 | bestMask
	fmtV := fdata << 10
	for i := 14; i > 9; i-- {
		if fmtV>>uint(i)&1 == 1 {
			fmtV ^= 0x537 << uint(i-10)
		}
	}
	fmtV = ((fdata << 10) | fmtV) ^ 0x5412
	put := func(r, c int, bit int) { best[r][c] = bit == 1 }
	for i := 0; i < 15; i++ {
		bit := (fmtV >> uint(i)) & 1
		if i < 6 {
			put(i, 8, bit)
		} else if i < 8 {
			put(i+1, 8, bit)
		} else {
			put(size-15+i, 8, bit)
		}
	}
	for i := 0; i < 15; i++ {
		bit := (fmtV >> uint(i)) & 1
		if i < 8 {
			put(8, size-1-i, bit)
		} else if i == 8 {
			put(8, 7, bit)
		} else {
			put(8, 14-i, bit)
		}
	}
	if v >= 7 {
		ver := v << 12
		for i := 17; i > 11; i-- {
			if ver>>uint(i)&1 == 1 {
				ver ^= 0x1F25 << uint(i-12)
			}
		}
		ver |= v << 12
		for i := 0; i < 18; i++ {
			bit := (ver >> uint(i)) & 1
			put(i/3, size-11+i%3, bit)
			put(size-11+i%3, i/3, bit)
		}
	}
	return best
}

func anyTrue(b []bool) bool {
	for _, v := range b {
		if v {
			return true
		}
	}
	return false
}

func absI(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// qrSVG renders the QR as a compact SVG string.
func qrSVG(data string) (string, error) {
	enc, err := qrEncode(data)
	if err != nil {
		return "", err
	}
	mat := qrMatrix(enc.v, enc.level, enc.cws)
	n := len(mat)
	quiet := 4
	sizePx := n + 2*quiet
	var sb strings.Builder
	for r := 0; r < n; r++ {
		runStart := -1
		for c := 0; c <= n; c++ {
			dark := c < n && mat[r][c]
			if dark && runStart < 0 {
				runStart = c
			} else if !dark && runStart >= 0 {
				fmt.Fprintf(&sb, `<rect x="%d" y="%d" width="%d" height="1"/>`, quiet+runStart, quiet+r, c-runStart)
				runStart = -1
			}
		}
	}
	body := sb.String()
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges" width="%d" height="%d"><rect width="%d" height="%d" fill="#ffffff"/><g fill="#0b0e16">%s</g></svg>`,
		sizePx, sizePx, sizePx*12, sizePx*12, sizePx, sizePx, body), nil
}
