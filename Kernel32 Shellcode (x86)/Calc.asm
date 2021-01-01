.386 
.model flat, stdcall 

ExitProcess PROTO STDCALL :DWORD
assume fs:nothing

.code 
main proc
	sub esp, 08h
	xor eax, eax
	mov [ebp - 04h], eax ; kernel32 imagebase address
	mov [ebp - 08h], eax ; Number of exported functions
	mov [ebp - 0Ch], eax ; Address of exported functions
	mov [ebp - 10h], eax ; Address of function names
	mov [ebp - 14h], eax ; Address of function (ordinals) numbers
	mov [ebp - 20h], eax ; WinExec string

	push 00636578h
	push 456e6957h
	mov [ebp - 20h], esp

	mov eax, [fs:30h]		    
	mov eax, [eax + 0ch]		
	mov eax, [eax + 14h]		
	mov eax, [eax]				
	mov eax, [eax]				
	mov eax, [eax -8h + 18h]
	
	mov [ebp-04h], eax
	mov ebx, [eax+3ch]
	add eax, ebx

	mov ebx, [eax+78h]
	mov eax, [ebp-04h]
	add eax, ebx

	mov ecx, [eax+14h]
	mov [ebp-08h], ecx

	mov ecx, [eax+1ch]
	mov [ebp-0ch], ecx

	mov ecx, [eax + 20h]
	add ecx, [ebp - 04h]
	mov [ebp - 10h], ecx

	mov ecx, [eax+18h]
	mov [ebp-14h], ecx

	; Finding WinExec Address
	xor eax, eax
	xor ecx, ecx
	mov ebx, [ebp - 04h]
	
	searchWinExec:
		mov edi, [ebp - 10h]; pointer to function names 
		mov esi, [ebp - 20h]; pointer to winExec
		cld
		mov edi, [edi + eax*4]
		add edi, ebx
		mov cx, 8
		REPE CMPSB
		jz runCalcUsingWinExec

		inc eax
		cmp eax, [ebp - 08h]
		jmp searchWinExec

	runCalcUsingWinExec:
		mov ecx, eax
		mov eax, [ebp-04h]
		add eax, [ebp-0ch]
		mov eax, [eax + ecx*4 + 4]
		add eax, [ebp - 04h]
		xor edx, edx
		push edx
		push 636c6163h
		mov ecx, esp
		push 10
		push ecx
		call eax

	invoke ExitProcess, 0
	
	mov ebx, 0	    
main endp
end main
