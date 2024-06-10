.code

InlineNtQueryInformationProcess PROC
	mov r10, rcx
	mov eax, 19h
	syscall
	ret
InlineNtQueryInformationProcess ENDP

end
