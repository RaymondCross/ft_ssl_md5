/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_sha224.h                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/16 23:24:24 by rcross            #+#    #+#             */
/*   Updated: 2019/07/17 20:52:09 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_SHA224_H

# define FT_SHA224_H

# include "ft_ssl.h"

# define RROT(X, N) ((X >> N) | (X << (32 - N)))
# define LROT(X, N) ((X << N) | (X >> (32 - N)))

# define A 0
# define B 1
# define C 2
# define D 3
# define E 4
# define F 5
# define G 6
# define H 7
# define S1(X) ((RROT(X, 6)) ^ (RROT(X, 11)) ^ (RROT(X, 25)))
# define CH(x, y, z) ((x & y) ^ (~ x & z))
# define S0(X) ((RROT(X, 2)) ^ (RROT(X, 13)) ^ (RROT(X, 22)))
# define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

typedef struct		s_sha224
{
	unsigned int	a_base;
	unsigned int	b_base;
	unsigned int	c_base;
	unsigned int	d_base;
	unsigned int	e_base;
	unsigned int	f_base;
	unsigned int	g_base;
	unsigned int	h_base;
	unsigned int	i;
	long long		len;
	unsigned int	out_len;
	unsigned char	*out;
	unsigned int	x;
	unsigned int	s0;
	unsigned int	s1;
	unsigned int	ch;
	unsigned int	maj;
	unsigned int	tmp1;
	unsigned int	tmp2;
	unsigned int	a;
	unsigned int	b;
	unsigned int	c;
	unsigned int	d;
	unsigned int	e;
	unsigned int	f;
	unsigned int	g;
	unsigned int	h;
	unsigned int	j;
	uint64_t		digest[7];
	unsigned int	bases[8];
}					t_sha224;

void				add_bufs224(t_sha224 *t);
void				setup_bufs224(t_sha224 *t);
int					find_output_len224(unsigned char *input);
unsigned int		rightrot224(unsigned int num, unsigned int rot);
void				get_digest224(t_sha224 *t);
void				main_loop224(t_sha224 *t);
void				setup_y224(t_sha224 *t);

#endif
