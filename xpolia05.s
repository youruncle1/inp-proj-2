; Autor reseni: Roman Poliacik xpolia05

; Projekt 2 - INP 2022
; Vernamova sifra na architekture MIPS64

; DATA SEGMENT
                .data
login:          .asciiz "xpolia05"  ; sem doplnte vas login
cipher:         .space  17  ; misto pro zapis sifrovaneho loginu

params_sys5:    .space  8   ; misto pro ulozeni adresy pocatku
                            ; retezce pro vypis pomoci syscall 5
                            ; (viz nize "funkce" print_string)

; CODE SEGMENT
                .text
                ; xpolia05-r12-r5-r16-r18-r0-r4          
                ; r12 vysledok porovnani / zisteni parnosti r5
                ; r5 indexing login(r5) / cipher(r5)
                ; r16 sifrovaci klic o hodnote 'p' (16), pripocitani
                ; r18 sifrovaci klic o hodnote 'o' (15), odecteni
                ; r0 pomocny register s hodnotou 0
                ; r4 nacteny znak
                
reginit:
                addi r16, r0, 16
                addi r18, r0, -15           

iterate:
                lb   r4, login(r5)            ;nacteni prvniho znaku z vstupu
                slti r12, r4, 97              ;ak je dec hodnota znaku < 97: r12 = 1
                bne  r12, r0, foundnumeric    ;r12 = 1, cifra na vstupu -> konec
                andi r12, r5, 1               ;index r5 parny/neparny? r12 = 0 : 1 (pouzitim and masking)
                bne  r12, r0, minus           ;ak r5 neparny, pokracuj minus
                
plus:           ;r5 je parny; pokracuj plus
                add  r4, r4, r16              ;pricitani sifrovaciho klice 'p'
                slti r12, r4, 123             ;check preteceni
                bne  r12, r0, store           ;kdyz je zasifrovany znak < 123, r12 = 1, muzu zapisovat
                
                ;nastalo preteceni
                addi r4, r4, -26              ;magicka konstanta in work
                b store                       ;preteceni napravene, muzu zapisovat

minus:
                add r4, r4, r18               ;odecteni sifrovaciho klice 'o'
                slti r12, r4, 97              ;check podteceni
                beq  r12, r0, store           ;kdyz je zasifrovany znak > 97, r12 = 0, muzu zapisovat
                
                ;nastalo podteceni
                addi r4, r4, 26               ;magicka konstanta in work

store:
                sb   r4, cipher(r5) 
                addi r5, r5, 1                ;index++
                b iterate
                
foundnumeric:
                addi  r5, r5, 1      ;index++
                sb    r0, cipher(r5) ;vlozenie nuly na koniec zapisovanych dat
                daddi r4, r0, cipher ;adresa cipher: do r4
                jal   print_string

                syscall 0

print_string:   ; adresa retezce se ocekava v r4
                sw      r4, params_sys5(r0)
                daddi   r14, r0, params_sys5    ; adr pro syscall 5 musi do r14
                syscall 5   ; systemova procedura - vypis retezce na terminal
                jr      r31 ; return - r31 je urcen na return address
