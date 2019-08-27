/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha256_helper.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/14 00:24:08 by rcross            #+#    #+#             */
/*   Updated: 2019/07/17 00:00:55 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_sha256.h"

void			add_bufs(t_sha256 *t)
{
	t->h0 = t->h0 + t->a;
	t->h1 = t->h1 + t->b;
	t->h2 = t->h2 + t->c;
	t->h3 = t->h3 + t->d;
	t->h4 = t->h4 + t->e;
	t->h5 = t->h5 + t->f;
	t->h6 = t->h6 + t->g;
	t->h7 = t->h7 + t->h;
}

void			setup_bufs(t_sha256 *t)
{
	t->a = t->h0;
	t->b = t->h1;
	t->c = t->h2;
	t->d = t->h3;
	t->e = t->h4;
	t->f = t->h5;
	t->g = t->h6;
	t->h = t->h7;
}

int				find_output_len(unsigned char *input)
{
	int len;
	int new_len;

	len = ft_strlen((char *)input);
	new_len = ((len + 8) / 64) * 64 + 64;
	return (new_len);
}

unsigned int	rightrot(unsigned int num, unsigned int rot)
{
	unsigned int i;
	unsigned int r;

	i = 0;
	while (i < rot)
	{
		r = num & 1;
		num = num >> 1;
		num += r << 31;
		i++;
	}
	return (num);
}
