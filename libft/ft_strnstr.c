/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strnstr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/27 14:39:20 by rcross            #+#    #+#             */
/*   Updated: 2019/03/03 15:47:59 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strnstr(const char *h, const char *n, size_t len)
{
	size_t	i;
	size_t	j;

	i = 0;
	if (!*n)
		return ((char *)h);
	while (h[i] && i < len)
	{
		j = 0;
		while (i + j < len && h[i + j] == n[j] && n[j] != '\0')
			j++;
		if (n[j] == '\0')
			return ((char *)h + i);
		i++;
	}
	return (NULL);
}
