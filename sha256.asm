include "sha256.inc"

hVec:
	dd	0x6a09e667,\
		0xbb67ae85,\
		0x3c6ef372,\
		0xa54ff53a,\
		0x510e527f,\
		0x9b05688c,\
		0x1f83d9ab,\
		0x5be0cd19
proc sha256 uses rbx, hashLp:qword, msgLp:qword
	locals
		hashBuf dd 8 dup(?)
		hashBuf.length = ($-hashBuf)/4
		lenstr dq ?
		bitsize dq ?
		; payload dq ?
		padding dq ?
		Blocks sha256Blocks
		stackFrame dq ?
		maxLp dq ?
	endl
	mov rax, Blocks.Table
	mov [hashLp], rcx
	mov [msgLp], rdx
	mov r8, hVec
	;перенос хэша
	mov r9, hashBuf.length/2-1
	.migrationHash:
		mov rax, [r8+r9*8]
		mov qword[hashBuf+r9*8], rax
	dec r9
	jns .migrationHash
	@call [strlen](rdx)
	mov [lenstr], rax
	shl rax, 3
	mov [bitsize], rax
	mov rax, [lenstr]
	add rax, 8
	xor rdx, rdx
	mov rcx, 64
	div rcx
	inc rax
	mov [Blocks.bCount], rax
	sub rdx, 64
	neg rdx
	mov [padding], rdx
	shl rax, 6
	stackAlloc [Blocks.blocksLp], [stackFrame], rax
	@call [strcpy]([Blocks.blocksLp], [msgLp])
	add rax, [lenstr]
	mov byte[rax], 10000000b
	inc rax
	dec [padding]
	mov rcx, [padding]
	test rcx, rcx
	jz .no_padding
		.paddfill:
			mov dword[rax+rcx-1], 0
		loop .paddfill
	.no_padding:
	add rax, [padding]
	mov rdx, [bitsize]
	bswap rdx
	mov qword[rax], rdx
	; доработать
	mov rbx, [Blocks.blocksLp]
	mov rcx, [Blocks.bCount]
	shl rcx, 6
	add rcx, rbx
	mov [maxLp], rcx
	.Expension:
		@call sha256Blocks.calcHash(rbx, addr hashBuf)
		add rbx, 64
	cmp rbx, [maxLp]
	jb .Expension
	;перенос хэша
	mov rcx, [hashLp]
	mov r9, hashBuf.length/2-1
	.returnHash:
		mov rax, qword[hashBuf+r9*8]
		mov [rcx+r9*8], rax
	dec r9
	jns .returnHash
	ret
endp


kTable:
	dd	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,\
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,\
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,\
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,\
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,\
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,\
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,\
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
proc sha256Blocks.calcHash, blockLp:qword, hashLp:qword
	locals
		hashBuf dd 8 dup(?)
		hashBuf.length = ($-hashBuf)/4
		Blocks sha256Blocks 4
		ExtendedBlock dd 64 dup(?)
		ExtendedBlock.length = ($-ExtendedBlock)/4
	endl
	virtual at rdx
		.a dd ?
		.b dd ?
		.c dd ?
		.d dd ?
		.e dd ?
		.f dd ?
		.g dd ?
		.h dd ?
	end virtual
	;перенос хэша
	mov r9, hashBuf.length/2-1
	.migrationHash:
		mov rax, [rdx+r9*8]
		mov qword[hashBuf+r9*8], rax
	dec r9
	jns .migrationHash
	mov [hashLp], rdx
	lea rdx, [hashBuf]
	lea rax, [ExtendedBlock]
	mov [Blocks.blocksLp], rax
	mov r9, ExtendedBlock.length-1
	;перенос блоков в big-endian
	.migrationBlocks:
		mov eax, [rcx+r9*4]
		bswap eax
		mov dword[ExtendedBlock+r9*4], eax
	dec r9
	jns .migrationBlocks
	; For i from w[16…63]:
	; 	s0 = (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] righthift 3)
	; 	s1 = (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] righthift 10)
	; 	w[i] = w[i-16] + s0 + w[i-7] + s1
	mov r9, 16
	.fillVoid:
		mov ecx, [ExtendedBlock+r9*4-15*4]
		sha256Blocks.C ecx, eax, 3, 7, 18
		mov r8d, [ExtendedBlock+r9*4-2*4] 
		sha256Blocks.C r8d, eax, 10, 17, 19
		add ecx, r8d
		add ecx, [ExtendedBlock+r9*4-16*4]
		add ecx, [ExtendedBlock+r9*4-7*4]
		mov [ExtendedBlock+r9*4], ecx
		inc r9
	cmp r9, ExtendedBlock.length
	jne .fillVoid
	; for i from 0 to 63
	; 	S1 = (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
	; 	ch = (e and f) xor ((not e) and g)
	; 	temp1 = h + S1 + ch + k[i] + w[i]
	; 	S0 = (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
	; 	maj = (a and b) xor (a and c) xor (b and c)
	; 	temp2 := S0 + maj
	; 	h = g
	; 	g = f
	; 	f = e
	; 	e = d + temp1
	; 	d = c
	; 	c = b
	; 	b = a
	; 	a = temp1 + temp2
	mov r9, 0
	.loopHashCalc:
		; S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
		mov ecx, [.e]
		sha256Blocks.S ecx, eax, 6, 11, 25
		; ch := (e and f) xor ((not e) and g)
		rol eax, 25
		mov r8d, eax
		not r8d
		and r8d, [.g]
		and eax, [.f]
		xor r8d, eax
		; temp1 := h + S1 + ch + k[i] + w[i]
		add ecx, r8d
		add ecx, [.h]
		add ecx, [kTable+r9*4]
		add ecx, [ExtendedBlock+r9*4]
		; S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
		mov r8d, [.a]
		sha256Blocks.S r8d, eax, 2, 13, 22
		; maj := (a and b) xor (a and c) xor (b and c)
		rol eax, 22
		mov r10d, [.b]
		mov r11d, r10d
		mov r12d, [.c]
		and r10d, eax
		and r11d, r12d
		and eax, r12d
		xor r10d, r11d
		xor r10d, eax
		; temp2 := S0 + maj
		add r8d, r10d
		; h := g
        mov eax, [.g]
        mov [.h], eax
        ; g := f
        mov eax, [.f]
        mov [.g], eax
        ; f := e
        mov eax, [.e]
        mov [.f], eax
        ; e := d + temp1
        mov eax, [.d]
        add eax, ecx
        mov [.e], eax
        ; d := c
        mov eax, [.c]
        mov [.d], eax
        ; c := b
        mov eax, [.b]
        mov [.c], eax
        ; b := a
        mov eax, [.a]
        mov [.b], eax
        ; a := temp1 + temp2
        add ecx, r8d
        mov [.a], ecx
        ; mov [.b], r8d
		inc r9
	cmp r9, 64
	jl .loopHashCalc
	mov rcx, [hashLp]
	lea r8, [hashBuf]
	mov r9, 7
	.finalAdd:
		mov r10d, [r8+r9*4]
		add [rcx+r9*4], r10d
	dec r9
	jns .finalAdd
	ret
endp

proc printHash uses rbx rsi, hashLp:qword, point:qword
	mov [hashLp], rcx
	mov [point], rdx
	xor rbx, rbx
	mov rsi, rcx
	@@:
		; mov ecx, [rsi+rbx*4]
		; @call [itoa](rcx, bitstr, 2, 8)
		; @call [strlen](bitstr)
		; @call [printf](<"%32s", 0Ah>, bitstr)
		mov edx, [rsi+rbx*4]
		@call [printf]("%x ")
		inc rbx
	cmp rbx, 8
	jne @b
	ret
endp

bitstr db 8 dup(0)
proc sha256Blocks.printBlocks uses rbx rsi rdi r12 r13
virtObj .this:arg sha256Blocks at rbx
	mov rbx, rcx
	mov rdi, [.this.bCount]
	shl rdi, 6
	add rdi, [.this.blocksLp]
	mov rsi, [.this.blocksLp]
	.loopNewLine:
		lea r12, [rsi+8]
		.loopSpace:
			mov ecx, dword[rsi]
			@call [itoa](rcx, bitstr, 2, 8)
			@call [strlen](bitstr)
			@call [printf](<"%32s ">, bitstr)
			add rsi, 4
		cmp rsi, r12
		jb .loopSpace
		@call [puts]("")
	cmp rsi, rdi
	jne .loopNewLine
	@call [puts]("")
	ret
endp