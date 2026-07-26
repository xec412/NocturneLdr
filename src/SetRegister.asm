; SetRegister.asm
.code

PUBLIC CaptureStackPointer

; Why assembly -> A c++ function call modifies RSP,
; so reading it directly in assembly is mandatory
CaptureStackPointer PROC
	mov rax, rsp
	ret
CaptureStackPointer ENDP

END