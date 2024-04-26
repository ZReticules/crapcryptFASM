format pe64 console

entry main

include "win64ax.inc" 
include "FASM_OOP\FASM_OOP.inc"

section ".src" readable writeable executable
	include "TOOLS\ParseCMD.asm"
	include "sha256.asm"

section ".data" readable writeable
	modstable:
		dq 	ccbc,\
			dcbc,\
			cecb,\
			decb

	mode dq ?			;ccbc dcbc cecb decb
	inputFileLp dq ?
	outputFileLp dq ?
	passwordLp dq ?
	sha256Hash dq 8 dup ?
section ".code" readable writeable executable

	proc ccbc
		@call [printf]("ccbc")
		ret
	endp

	proc dcbc
		@call [printf]("dcbc")
		ret
	endp

	proc cecb
		@call [printf]("cecb")
		ret
	endp

	proc decb
		@call [printf]("decb")
		ret
	endp

	proc main
		local argc:DWORD, argv:QWORD
		@call ParseCommandLine(addr argv)
		mov [argc], eax
		dec eax
		cmp eax, 4
			jne ErrorOut
		@call [SetConsoleCP](1251)
		@call [SetConsoleOutputCP](1251)
		mov rsi, [argv]
		virtual at rsi
			argLpLp dq ?
		end virtual
		;получаем режим
		mov rax, qword[argLpLp+1*8]
		movzx eax, word[rax]
		sub eax, "cc"
		add al, ah
		and rax, 0x3
		mov rax, [modstable+rax*8]
		mov [mode], rax
		;получаем адрес файла-источника
		mov rax, qword[argLpLp+2*8]
		mov [inputFileLp], rax
		;получаем адрес файла-приемника
		mov rax, qword[argLpLp+3*8]
		mov [outputFileLp], rax
		;получаем указатель на пароль
		mov rax, qword[argLpLp+4*8]
		cmp byte[rax], '"'
		jne .removeQuotes
			inc rax
			mov rdx, rax
			.findQuote:
				inc rdx
				cmp byte[rdx], '"'
				jne .testZero
					mov byte[rdx], 0
				.testZero:
			cmp byte[rdx], 0
			jne .findQuote
		.removeQuotes:
		mov [passwordLp], rax
		;заполняем блоки
		@call sha256(sha256Hash, rax)
		@call printHash(sha256Hash)
		@call [ExitProcess](0)

	ErrorOut:
		@call [printf](<"Something went wrong. Args:", 0Ah>)
		mov rsi, [argv]
		xor rbx, rbx
		@@:
			@call [printf](<"%d. %s", 0Ah>, addr rbx+1, qword[rsi+rbx*8])
		inc rbx
		cmp ebx, [argc]
		jb @b
		@call [ExitProcess](0)
	endp

section "idata" import readable writeable
	library kernel32, "kernel32.dll",\
			msvcrt, "msvcrt.dll"

	import kernel32, \
			ExitProcess, "ExitProcess", \
			SetConsoleCP, "SetConsoleCP", \
			SetConsoleOutputCP, "SetConsoleOutputCP",\
			GetCommandLineA, "GetCommandLineA"

	import msvcrt,\
			getch, "_getwch",\
			printf, "printf",\
			puts, "puts",\
			malloc, "malloc",\
			strlen, "strlen",\
			strcpy, "strcpy",\
			free, "free",\
			itoa, "_itoa"