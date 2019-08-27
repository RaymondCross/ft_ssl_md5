/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsub.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/27 14:40:21 by rcross            #+#    #+#             */
/*   Updated: 2019/03/10 20:51:03 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

/*
** Allocates with malloc(), and returns a “fresh” substring from the string
** given as argument. The substring begins at indexstart and is of size len.
** If start and len aren’t refering to a valid substring, the behavior is
** undefined. If the allocation fails, the function returns NULL.
*/

char	*ft_strsub(char const *s, unsigned int start, size_t len)
{
	int		x;
	char	*tmp;
	size_t	i;

	i = 0;
	x = start;
	if (!s)
		return (NULL);
	tmp = (char *)malloc(sizeof(char) * len + 1);
	if (!tmp)
		return (NULL);
	while (s[x] && i < len)
	{
		tmp[i] = s[x];
		i++;
		x++;
	}
	tmp[i] = '\0';
	return (tmp);
}
