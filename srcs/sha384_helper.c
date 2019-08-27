/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha384_helper.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/24 19:04:15 by rcross            #+#    #+#             */
/*   Updated: 2019/07/24 19:04:15 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_sha384.h"

uint64_t		swap_int64_384(const uint64_t val)
{
	return ((((val) & 0xff00000000000000ull) >> 56) |
			(((val) & 0x00ff000000000000ull) >> 40) |
			(((val) & 0x0000ff0000000000ull) >> 24) |
			(((val) & 0x000000ff00000000ull) >> 8) |
			(((val) & 0x00000000ff000000ull) << 8) |
			(((val) & 0x0000000000ff0000ull) << 24) |
			(((val) & 0x000000000000ff00ull) << 40) |
			(((val) & 0x00000000000000ffull) << 56));
}

void			init_tmp_words384(uint64_t *w, uint64_t *block)
{
	int			i;
	uint64_t	tmp_1;
	uint64_t	tmp_2;

	ft_memcpy(w, block, 16 * sizeof(uint64_t));
	i = -1;
	i = 15;
	while (++i < 80)
	{
		tmp_1 = SIG0(w[i - 15]);
		tmp_2 = SIG1(w[i - 2]);
		w[i] = w[i - 16] + tmp_1 + w[i - 7] + tmp_2;
	}
}

size_t			calc_bytenum384(size_t slen)
{
	(slen += 8);
	while (slen * 8 % 1024)
		slen++;
	return (slen);
}
