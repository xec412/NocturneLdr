; ShadowGate.asm
.code

; RCX = SHADOWGATE_PARAMS* (pointer to parameter structure)
ShadowGate PROC

	;---------------------------- SAVE NON-VOLATILE REGISTERS ;----------------------------
	push rbx
	push rbp
	push rsi
	push rdi
	push r12
	push r13
	push r14
	push r15

	mov r12, rcx							; R12 = SHADOWGATE_PARAMS*
	mov r13, [r12]							; R13 = pFunction (Offset -> 0)
	mov r14, [r12 + 8h]						; R14 = dwMinimumFrameSize (Offset -> 8)
	mov r15, [r12 + 10h]					; R15 = argc (Offset -> 10)
	lea rbp, [r12 + 18h]					; RBP = &argv[0] (Offset -> 18)

	sub rsp, r14							; <- Core of stack spoofing

	;---------------------------- LOAD ARGUMENTS ;----------------------------
	cmp r15, 0
	jle DoCall

	mov rcx, [rbp]							; argv[0] -> RCX
	cmp r15, 1
	jle DoCall

	mov rdx, [rbp + 8h]						; argv[1] -> RDX
	cmp r15, 2
	jle DoCall

	mov r8, [rbp + 10h]						; argv[2] -> R8
	cmp r15, 3
	jle DoCall

	mov r9, [rbp + 18h]						; argv[3] -> R9
	cmp r15, 4
	jle DoCall

	; 5+ arguments: write past shadow space onto stack
	mov rbx, rcx
	lea rsi, [rbp + 20h]					; Source: &argv[4]
	lea rdi, [rsp + 28h]					; Destination: RSP + shadow (0x20) + ret(0x8)
	mov rcx, r15
	sub rcx, 4
	rep movsq
	mov rcx, rbx

DoCall:
	test r13, r13
	jz Skip
	call r13								; <- TARGET FUNC CALLED HERE

Skip:
	add rsp, r14							; Restore stack pointer

	pop r15
	pop r14
	pop r13
	pop r12
	pop rdi
	pop rsi
	pop rbp
	pop rbx

	ret
ShadowGate ENDP

ShadowGateEnd PROC
	ret
ShadowGateEnd ENDP

END