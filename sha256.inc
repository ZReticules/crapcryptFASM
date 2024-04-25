struct sha256Blocks
	printBlocks method this
	bCount dq ?
	blocksLp dq ?
ends

macro sha256Blocks.C dest:reg, uses:reg, sh, ror1, ror2{
	mov uses, dest
	shr uses, sh
	ror dest, ror1
	xor uses, dest
	ror dest, ror2-ror1
	xor dest, uses
}

macro sha256Blocks.S dest:reg, uses:reg, ror1, ror2, ror3{
	mov uses, dest
	ror dest, ror1
	ror uses, ror2
	xor dest, uses
	ror uses, ror3-ror2
	xor dest, uses
}

macro stackAlloc Dest, StackFrame, Size{
	mov StackFrame, rsp
	sub rsp, Size
	mov Dest, rsp
}