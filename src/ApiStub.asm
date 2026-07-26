; ApiStub.asm
.code

;===========================================
; StubProxyNtProtectVirtualMemory Procedure
;===========================================
StubProxyNtProtectVirtualMemory PROC
	push rbx					; Backup RBX value
	mov rbx, rcx				; Backup PROTECT_MEMORY_CTX structure into a nonvol register

	mov rax, [rbx]				; Move NtProtectVirtualMemory into RAX

	; ====== REGISTER PARAMETERS ;======
	mov rcx, [rbx + 8h]			; Move ProcessHandle parameter into RCX
	mov rdx, [rbx + 10h]		; Move *BaseAddress parameter into RDX
	mov r8, [rbx + 18h]			; Move RegionSize parameter into R8
	mov r9, [rbx + 20h]			; Move NewProtection parameter into R9

	; ====== STACK PARAMETERS ; ======
	mov r10, [rbx + 28h]		; Move OldProtection parameter into r10
	mov [rsp + 30h], r10		; Push onto the stack

	pop rbx						; Restore RBX value
	jmp rax						; Jump directly to NtProtectVirtualMemory
StubProxyNtProtectVirtualMemory ENDP

END