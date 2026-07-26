; Unguard.asm
.code

; RCX = Target address to dereference
; RDX = Gadget address (MOV RAX, [RAX]; RET inside a signed module)
; RAX = Dereferenced value
;
; If RDX is NULL, performs a normal read from the current context.
; If RDX is non-NULL, jumps to the gadget so the read occurs
; inside a legitimate module frame — bypassing EAF hardware breakpoints.

ShieldedRead PROC
	test rdx, rdx				; Check if gadget is provided
	jz DirectRead

	mov rax, rcx				; RAX = target address
	jmp rdx						; Jump to gadget (MOV RAX, [RAX]; RET)

DirectRead:
	mov rax, [rcx]				; Normal dereference
	ret

ShieldedRead ENDP

END
