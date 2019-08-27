/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_sha256.h                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/14 00:18:18 by rcross            #+#    #+#             */
/*   Updated: 2019/07/17 00:04:50 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_SHA256_H

# define FT_SHA256_H

# include "ft_ssl.h"

typedef struct		s_sha256
{
	unsigned int	h0;
	unsigned int	h1;
	unsigned int	h2;
	unsigned int	h3;
	unsigned int	h4;
	unsigned int	h5;
	unsigned int	h6;
	unsigned int	h7;
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
	uint64_t		digest[8];
}					t_sha256;

void				add_bufs(t_sha256 *t);
void				setup_bufs(t_sha256 *t);
int					find_output_len(unsigned char *input);
unsigned int		rightrot(unsigned int num, unsigned int rot);
void				get_digest(t_sha256 *t);
void				main_loop(t_sha256 *t);
void				setup_m(t_sha256 *t);

#endif
