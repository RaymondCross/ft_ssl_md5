/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strjoin.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/27 14:36:55 by rcross            #+#    #+#             */
/*   Updated: 2019/03/10 21:25:22 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

/*
** Allocates with malloc() and returns a “fresh” string ending with ’\0’,
** result of the concatenation of s1 and s2. If the allocation fails the
** function returns NULL.
*/

char	*ft_strjoin(char const *s1, char const *s2)
{
	int		i;
	int		j;
	char	*tmp;

	i = 0;
	j = 0;
	if (!s1 || !s2)
		return (0);
	tmp = (char *)malloc(sizeof(char) * ft_strlen(s1) + ft_strlen(s2) + 2);
	if (!tmp)
		return (NULL);
	while (s1[i])
	{
		tmp[i] = s1[i];
		i++;
	}
	while (s2[j])
	{
		tmp[i + j] = s2[j];
		j++;
	}
	tmp[i + j] = '\0';
	return (tmp);
}
