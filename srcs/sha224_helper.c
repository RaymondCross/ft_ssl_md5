/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha224_helper.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/16 23:24:22 by rcross            #+#    #+#             */
/*   Updated: 2019/07/16 23:24:23 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_sha224.h"

void			add_bufs224(t_sha224 *t)
{
	t->a_base = t->a_base + t->a;
	t->b_base = t->b_base + t->b;
	t->c_base = t->c_base + t->c;
	t->d_base = t->d_base + t->d;
	t->e_base = t->e_base + t->e;
	t->f_base = t->f_base + t->f;
	t->g_base = t->g_base + t->g;
	t->h_base = t->h_base + t->h;
}

void			setup_bufs224(t_sha224 *t)
{
	t->a = t->a_base;
	t->b = t->b_base;
	t->c = t->c_base;
	t->d = t->d_base;
	t->e = t->e_base;
	t->f = t->f_base;
	t->g = t->g_base;
	t->h = t->h_base;
}

int				find_output_len224(unsigned char *input)
{
	int len;
	int new_len;

	len = ft_strlen((char *)input);
	new_len = ((len + 8) / 64) * 64 + 64;
	return (new_len);
}

unsigned int	rightrot224(unsigned int num, unsigned int rot)
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
