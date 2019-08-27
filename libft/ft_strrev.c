/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strrev.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/03 00:30:33 by rcross            #+#    #+#             */
/*   Updated: 2019/06/03 00:31:47 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void			ft_strrev(char *str)
{
	char	*pointer;

	pointer = str;
	while (*pointer)
		pointer++;
	pointer--;
	while (str < pointer)
	{
		ft_charswap(&(*str), &(*pointer));
		str++;
		pointer--;
	}
}
