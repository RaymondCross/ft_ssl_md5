/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memrev.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/17 21:59:01 by rcross            #+#    #+#             */
/*   Updated: 2019/07/17 21:59:01 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_memrev(void *mem, size_t num)
{
	size_t			i;
	unsigned char	*mem_start;
	unsigned char	*mem_end;
	unsigned char	buf;

	mem_start = mem;
	mem_end = mem_start + num - 1;
	i = num / 2;
	while (i--)
	{
		buf = *mem_start;
		*mem_start++ = *mem_end;
		*mem_end-- = buf;
	}
}
