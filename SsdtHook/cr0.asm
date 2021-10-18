.CODE  ;代码段

DisableWriteProtect PROC            ;去除写保护
         cli                        ;关中断
         push  rax;
         push  rbx;

         mov   rax, cr0;
         mov   rbx, rax;
         and   rax, 0FFFEFFFFh;     ; CR0 16 BIT = 0
         mov   cr0, rax;
     

         mov   rax,rcx              ; rcx = pOldAttr
         mov   [rax],rbx
         
         pop   rbx;
         pop   rax;
         ret
DisableWriteProtect ENDP  






EnableWriteProtect  PROC             ;恢复写保护

         push  rax;
         mov   rax, rcx; 
         mov   cr0, rax;
         pop   rax;
         sti                          ;开中断
         ret

EnableWriteProtect  ENDP



END     
