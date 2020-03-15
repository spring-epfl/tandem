/**
 * Copyright 2017 Manuel Barbosa, mbb@dcc.fc.up.pt
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef BHJL_HEADER
#define BHJL_HEADER

int bhjl_encrypt_r(mpz_t c,const mpz_t m, const mpz_t x,
				 const mpz_t n,const mpz_t y, const int k,
				 const mpz_t _2k);

int bhjl_encrypt(mpz_t c,const mpz_t m,
                 const mpz_t n,const mpz_t y, const int k,
                 const mpz_t _2k,
                 gmp_randstate_t gmpRandState);

int bhjl_decrypt(mpz_t m,const mpz_t c,
                 const mpz_t p,const mpz_t D,const int k,
                 const mpz_t _2k1,const mpz_t pm12k);

int bhjl_homadd(mpz_t c, const mpz_t c1, const mpz_t c2,
                const mpz_t n);

int bhjl_homsub(mpz_t c, const mpz_t c1, const mpz_t c2,
                const mpz_t n);

int bhjl_homsmul(mpz_t c, const mpz_t c1, const mpz_t s,
                 const mpz_t n);

#endif
