/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_numlen_base.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/04 01:54:35 by rcross            #+#    #+#             */
/*   Updated: 2019/06/04 01:54:54 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int			ft_numlen_base(unsigned long long num, int base)
{
	int		i;

	if (num == 0)
		return (1);
	i = 0;
	while (num > 0)
	{
		i++;
		num /= base;
	}
	return (i);
}
