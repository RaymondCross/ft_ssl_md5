/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa_base_lower.c                               :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/03 14:10:27 by rcross            #+#    #+#             */
/*   Updated: 2019/06/03 14:10:34 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

/*
** Takes an int, and converts it to a null-terminated string with lowercase
** letters and with a specific numeric base (from binary to hexadecimal).
*/

char		*ft_itoa_base_lower(int value, int base)
{
	long	nbr;
	int		len;
	char	*pointer;
	char	*base_string;

	if (value == 0 || base < 2 || base > 16)
		return (ft_strdup("0"));
	nbr = value;
	len = ft_nbrlen(nbr, base);
	base_string = "0123456789abcdef";
	nbr < 0 ? nbr *= -1 : 0;
	if (!(pointer = (char *)malloc(sizeof(char) * len + 1)))
		return (NULL);
	pointer[len] = '\0';
	while (nbr)
	{
		pointer[--len] = base_string[nbr % base];
		nbr /= base;
	}
	if ((value < 0) && (base == 10))
		pointer[0] = '-';
	return (pointer);
}
