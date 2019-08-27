/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strmapi.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/27 14:37:35 by rcross            #+#    #+#             */
/*   Updated: 2019/03/03 15:47:53 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strmapi(char const *s, char (*f)(unsigned int, char))
{
	size_t		i;
	char		*tmp;

	i = 0;
	if (!s || !f)
		return (NULL);
	tmp = (char *)malloc(sizeof(char) * ft_strlen(s) + 1);
	if (tmp)
	{
		while (s[i])
		{
			tmp[i] = f(i, s[i]);
			i++;
		}
		tmp[i] = '\0';
		return (tmp);
	}
	return (NULL);
}
