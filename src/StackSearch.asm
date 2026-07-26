; StackSearch.asm
.code

; RCX = QWORD value to search for (BTIT + CallOffset)
; RDX = Pointer where the found address will be written
; RAX = Byte offset from RSP to found address

ScanStackForValue PROC
	mov r8, rsp						; R8 = Starting RSP (reference point)
	mov r9, gs:[08h]				; Get StackBase field from the TEB

	mov r10, r8						; R10 = Search pointer (starting from rsp)

SearchLoop:
	cmp r10, r9						; Have we reached StackBase?
	jae NotFound					; Yes -> Not Found

	cmp qword ptr [r10], rcx		; Does [r10] equal the value we are looking for?
	je Found						; Yes -> Found

	add r10, 8						; Advance by 8 bytes (Each stack slot is 8 bytes on x64)
	jmp SearchLoop

Found:
	mov rax, r10					; RAX = Address where value was found
	mov [rdx], r10					; *RDX = Found Address (out param)
	sub rax, r8						; RAX = Found address - starting rsp = offset
	ret

NotFound:
	xor rax, rax
	ret

ScanStackForValue ENDP

END