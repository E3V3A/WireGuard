/* Copyright 2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * - Redistributions of source code must retain copyright notices,
 * this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials
 * provided with the distribution.
 * - Neither the name of the CRYPTOGAMS nor the names of its
 * copyright holder and contributors may be used to endorse or
 * promote products derived from this software without specific
 * prior written permission.
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL), in which case the provisions of the GPL apply INSTEAD OF
 * those given above.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#if !defined(CONFIG_64BIT)
#error "This is only for 64-bit kernels."
#endif

#ifdef __MIPSEB__
#define MSB 0
#define LSB 7
#else
#define MSB 7
#define LSB 0
#endif

#if defined(CONFIG_CPU_MIPS64_R6) || defined(CONFIG_CPU_MIPSR6)
#define dmultu(rs,rt)
#define mflo(rd,rs,rt)	dmulu	rd,rs,rt
#define mfhi(rd,rs,rt)	dmuhu	rd,rs,rt
#else
#define dmultu(rs,rt)		dmultu	rs,rt
#define multu(rs,rt)		multu	rs,rt
#define mflo(rd,rs,rt)	mflo	rd
#define mfhi(rd,rs,rt)	mfhi	rd
#endif

.text
.set	noat
.set	noreorder

/* While most of the assembly in the kernel prefers ENTRY() and ENDPROC(),
 * there is no existing MIPS assembly that uses it, and MIPS assembler seems
 * to like its own .ent/.end notation, which the MIPS include files don't
 * provide in a MIPS-specific ENTRY/ENDPROC definition. So, we skip these
 * for now, until somebody complains. */

.align	5
.globl	poly1305_init_mips
.ent	poly1305_init_mips
poly1305_init_mips:
	.frame	$29,0,$31
	.set	reorder

	sd	$0,0($4)
	sd	$0,8($4)
	sd	$0,16($4)

	beqz	$5,.Lno_key

#if defined(CONFIG_CPU_MIPS64_R6) || defined(CONFIG_CPU_MIPSR6)
	ld	$8,0($5)
	ld	$9,8($5)
#else
	ldl	$8,0+MSB($5)
	ldl	$9,8+MSB($5)
	ldr	$8,0+LSB($5)
	ldr	$9,8+LSB($5)
#endif
#ifdef	__MIPSEB__
#if defined(CONFIG_CPU_MIPS64_R2) || defined(CONFIG_CPU_MIPSR2) || defined(CONFIG_CPU_MIPS64_R6) || defined(CONFIG_CPU_MIPSR6)
	dsbh	$8,$8		# byte swap
	 dsbh	$9,$9
	dshd	$8,$8
	 dshd	$9,$9
#else
	ori	$10,$0,0xFF
	dsll	$1,$10,32
	or	$10,$1		# 0x000000FF000000FF

	and	$11,$8,$10	# byte swap
	 and	$2,$9,$10
	dsrl	$1,$8,24
	 dsrl	$24,$9,24
	dsll	$11,24
	 dsll	$2,24
	and	$1,$10
	 and	$24,$10
	dsll	$10,8			# 0x0000FF000000FF00
	or	$11,$1
	 or	$2,$24
	and	$1,$8,$10
	 and	$24,$9,$10
	dsrl	$8,8
	 dsrl	$9,8
	dsll	$1,8
	 dsll	$24,8
	and	$8,$10
	 and	$9,$10
	or	$11,$1
	 or	$2,$24
	or	$8,$11
	 or	$9,$2
	dsrl	$11,$8,32
	 dsrl	$2,$9,32
	dsll	$8,32
	 dsll	$9,32
	or	$8,$11
	 or	$9,$2
#endif
#endif
	li	$10,1
	dsll	$10,32
	daddiu	$10,-63
	dsll	$10,28
	daddiu	$10,-1		# 0ffffffc0fffffff

	and	$8,$10
	daddiu	$10,-3		# 0ffffffc0ffffffc
	and	$9,$10

	sd	$8,24($4)
	dsrl	$10,$9,2
	sd	$9,32($4)
	daddu	$10,$9		# s1 = r1 + (r1 >> 2)
	sd	$10,40($4)

.Lno_key:
	li	$2,0			# return 0
	jr	$31
.end	poly1305_init_mips

.align	5
.globl	poly1305_blocks_mips
.ent	poly1305_blocks_mips
poly1305_blocks_mips:
	.set	noreorder
	dsrl	$6,4			# number of complete blocks
	bnez	$6,poly1305_blocks_internal
	nop
	jr	$31
	nop
.end	poly1305_blocks_mips

.align	5
.ent	poly1305_blocks_internal
poly1305_blocks_internal:
	.frame	$29,6*8,$31
	.mask	0x00030000,-8
	.set	noreorder
	dsubu	$29,6*8
	sd	$17,40($29)
	sd	$16,32($29)
	.set	reorder

	ld	$12,0($4)		# load hash value
	ld	$13,8($4)
	ld	$14,16($4)

	ld	$15,24($4)		# load key
	ld	$16,32($4)
	ld	$17,40($4)

.Loop:
#if defined(CONFIG_CPU_MIPS64_R6) || defined(CONFIG_CPU_MIPSR6)
	ld	$8,0($5)		# load input
	ld	$9,8($5)
#else
	ldl	$8,0+MSB($5)	# load input
	ldl	$9,8+MSB($5)
	ldr	$8,0+LSB($5)
	ldr	$9,8+LSB($5)
#endif
	daddiu	$6,-1
	daddiu	$5,16
#ifdef	__MIPSEB__
#if defined(CONFIG_CPU_MIPS64_R2) || defined(CONFIG_CPU_MIPSR2) || defined(CONFIG_CPU_MIPS64_R6) || defined(CONFIG_CPU_MIPSR6)
	dsbh	$8,$8		# byte swap
	 dsbh	$9,$9
	dshd	$8,$8
	 dshd	$9,$9
#else
	ori	$10,$0,0xFF
	dsll	$1,$10,32
	or	$10,$1		# 0x000000FF000000FF

	and	$11,$8,$10	# byte swap
	 and	$2,$9,$10
	dsrl	$1,$8,24
	 dsrl	$24,$9,24
	dsll	$11,24
	 dsll	$2,24
	and	$1,$10
	 and	$24,$10
	dsll	$10,8			# 0x0000FF000000FF00
	or	$11,$1
	 or	$2,$24
	and	$1,$8,$10
	 and	$24,$9,$10
	dsrl	$8,8
	 dsrl	$9,8
	dsll	$1,8
	 dsll	$24,8
	and	$8,$10
	 and	$9,$10
	or	$11,$1
	 or	$2,$24
	or	$8,$11
	 or	$9,$2
	dsrl	$11,$8,32
	 dsrl	$2,$9,32
	dsll	$8,32
	 dsll	$9,32
	or	$8,$11
	 or	$9,$2
#endif
#endif
	daddu	$12,$8		# accumulate input
	daddu	$13,$9
	sltu	$10,$12,$8
	sltu	$11,$13,$9
	daddu	$13,$10

	dmultu	($15,$12)		# h0*r0
	 daddu	$14,$7
	 sltu	$10,$13,$10
	mflo	($8,$15,$12)
	mfhi	($9,$15,$12)

	dmultu	($17,$13)		# h1*5*r1
	 daddu	$10,$11
	 daddu	$14,$10
	mflo	($10,$17,$13)
	mfhi	($11,$17,$13)

	dmultu	($16,$12)		# h0*r1
	 daddu	$8,$10
	 daddu	$9,$11
	mflo	($1,$16,$12)
	mfhi	($25,$16,$12)
	 sltu	$10,$8,$10
	 daddu	$9,$10

	dmultu	($15,$13)		# h1*r0
	 daddu	$9,$1
	 sltu	$1,$9,$1
	mflo	($10,$15,$13)
	mfhi	($11,$15,$13)
	 daddu	$25,$1

	dmultu	($17,$14)		# h2*5*r1
	 daddu	$9,$10
	 daddu	$25,$11
	mflo	($1,$17,$14)

	dmultu	($15,$14)		# h2*r0
	 sltu	$10,$9,$10
	 daddu	$25,$10
	mflo	($2,$15,$14)

	daddu	$9,$1
	daddu	$25,$2
	sltu	$1,$9,$1
	daddu	$25,$1

	li	$10,-4		# final reduction
	and	$10,$25
	dsrl	$11,$25,2
	andi	$14,$25,3
	daddu	$10,$11
	daddu	$12,$8,$10
	sltu	$10,$12,$10
	daddu	$13,$9,$10
	sltu	$10,$13,$10
	daddu	$14,$14,$10

	bnez	$6,.Loop

	sd	$12,0($4)		# store hash value
	sd	$13,8($4)
	sd	$14,16($4)

	.set	noreorder
	ld	$17,40($29)		# epilogue
	ld	$16,32($29)
	jr	$31
	daddu	$29,6*8
.end	poly1305_blocks_internal

.align	5
.globl	poly1305_emit_mips
.ent	poly1305_emit_mips
poly1305_emit_mips:
	.frame	$29,0,$31
	.set	reorder

	ld	$10,0($4)
	ld	$11,8($4)
	ld	$1,16($4)

	daddiu	$8,$10,5		# compare to modulus
	sltiu	$2,$8,5
	daddu	$9,$11,$2
	sltu	$2,$9,$2
	daddu	$1,$1,$2

	dsrl	$1,2			# see if it carried/borrowed
	dsubu	$1,$0,$1
	nor	$2,$0,$1

	and	$8,$1
	and	$10,$2
	and	$9,$1
	and	$11,$2
	or	$8,$10
	or	$9,$11

	lwu	$10,0($6)		# load nonce
	lwu	$11,4($6)
	lwu	$1,8($6)
	lwu	$2,12($6)
	dsll	$11,32
	dsll	$2,32
	or	$10,$11
	or	$1,$2

	daddu	$8,$10		# accumulate nonce
	daddu	$9,$1
	sltu	$10,$8,$10
	daddu	$9,$10

	dsrl	$10,$8,8		# write mac value
	dsrl	$11,$8,16
	dsrl	$1,$8,24
	sb	$8,0($5)
	dsrl	$2,$8,32
	sb	$10,1($5)
	dsrl	$10,$8,40
	sb	$11,2($5)
	dsrl	$11,$8,48
	sb	$1,3($5)
	dsrl	$1,$8,56
	sb	$2,4($5)
	dsrl	$2,$9,8
	sb	$10,5($5)
	dsrl	$10,$9,16
	sb	$11,6($5)
	dsrl	$11,$9,24
	sb	$1,7($5)

	sb	$9,8($5)
	dsrl	$1,$9,32
	sb	$2,9($5)
	dsrl	$2,$9,40
	sb	$10,10($5)
	dsrl	$10,$9,48
	sb	$11,11($5)
	dsrl	$11,$9,56
	sb	$1,12($5)
	sb	$2,13($5)
	sb	$10,14($5)
	sb	$11,15($5)

	jr	$31
.end	poly1305_emit_mips
