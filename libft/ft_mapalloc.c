/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_mapalloc.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/04 18:21:32 by rcross            #+#    #+#             */
/*   Updated: 2019/04/04 21:35:10 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char			**ft_mapalloc(int i, int j)
{
	char		**map;
	int			k;

	k = 0;
	if (!(map = (char **)malloc(sizeof(char *) * i + 1)))
		return (NULL);
	while (k < i)
	{
		map[k] = ft_strnew(j);
		k++;
	}
	map[k] = NULL;
	return (map);
}
