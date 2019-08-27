/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha224.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/16 23:24:19 by rcross            #+#    #+#             */
/*   Updated: 2019/07/17 21:14:13 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_sha224.h"

unsigned int g_y[64];
unsigned int g_z[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static void	init_sha224(t_sha224 *t, unsigned char *input)
{
	t->a_base = 0xc1059ed8;
	t->b_base = 0x367cd507;
	t->c_base = 0x3070dd17;
	t->d_base = 0xf70e5939;
	t->e_base = 0xffc00b31;
	t->f_base = 0x68581511;
	t->g_base = 0x64f98fa7;
	t->h_base = 0xbefa4fa4;
	t->out_len = find_output_len224(input);
	t->out = (unsigned char*)ft_strnew(t->out_len);
	ft_strcpy((char *)t->out, (char *)input);
	t->len = ft_strlen((char *)input) * 8;
	t->out[ft_strlen((char *)input)] = 1 << 7;
	t->i = 0;
	while (t->i < 8)
	{
		t->out[t->out_len - 8 + t->i] = ((unsigned char *)&(t->len))[7 - t->i];
		t->i++;
	}
	t->i = 0;
}

void		setup_y224(t_sha224 *t)
{
	t->x = 0;
	while (t->x < 16)
	{
		g_y[t->x] = 0;
		g_y[t->x] += t->out[t->i * 64 + t->x * 4 + 0] << 24;
		g_y[t->x] += t->out[t->i * 64 + t->x * 4 + 1] << 16;
		g_y[t->x] += t->out[t->i * 64 + t->x * 4 + 2] << 8;
		g_y[t->x] += t->out[t->i * 64 + t->x * 4 + 3] << 0;
		t->x++;
	}
	while (t->x < 64)
	{
		t->s0 = rightrot224(g_y[t->x - 15], 7) ^ rightrot224(g_y[t->x - 15], 18)
			^ (g_y[t->x - 15] >> 3);
		t->s1 = rightrot224(g_y[t->x - 2], 17) ^ rightrot224(g_y[t->x - 2], 19)
			^ (g_y[t->x - 2] >> 10);
		g_y[t->x] = g_y[t->x - 16] + t->s0 + g_y[t->x - 7] + t->s1;
		t->x++;
	}
}

void		main_loop224(t_sha224 *t)
{
	t->j = 0;
	while (t->j < 64)
	{
		t->s1 = rightrot224(t->e, 6) ^ rightrot224(t->e, 11) ^
			rightrot224(t->e, 25);
		t->ch = (t->e & t->f) ^ ((~t->e) & t->g);
		t->tmp1 = t->h + t->s1 + t->ch + g_z[t->j] + g_y[t->j];
		t->s0 = rightrot224(t->a, 2) ^ rightrot224(t->a, 13) ^
			rightrot224(t->a, 22);
		t->maj = (t->a & t->b) ^ (t->a & t->c) ^ (t->b & t->c);
		t->tmp2 = t->s0 + t->maj;
		t->h = t->g;
		t->g = t->f;
		t->f = t->e;
		t->e = t->d + t->tmp1;
		t->d = t->c;
		t->c = t->b;
		t->b = t->a;
		t->a = t->tmp1 + t->tmp2;
		t->j++;
	}
}

void		get_digest224(t_sha224 *t)
{
	t->digest[0] = t->a_base;
	t->digest[1] = t->b_base;
	t->digest[2] = t->c_base;
	t->digest[3] = t->d_base;
	t->digest[4] = t->e_base;
	t->digest[5] = t->f_base;
	t->digest[6] = t->g_base;
}

void		sha224(t_ssl *ssl)
{
	t_sha224	t;
	int			i;

	i = -1;
	while (++i < ssl->p_size)
	{
		init_sha224(&t, (unsigned char *)ssl->to_hash[i]);
		while (t.i < (t.out_len * 8) / 512)
		{
			setup_y224(&t);
			setup_bufs224(&t);
			main_loop224(&t);
			add_bufs224(&t);
			t.i++;
		}
		get_digest224(&t);
		output_64(ssl, t.digest, i);
		free(t.out);
	}
}
