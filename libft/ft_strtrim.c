/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strtrim.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/27 14:40:41 by rcross            #+#    #+#             */
/*   Updated: 2019/03/03 18:20:51 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strtrim(char const *s)
{
	int		i;
	int		j;
	char	*tmp;

	if (!s)
		return (NULL);
	i = 0;
	while (s[i] && ft_iswhitespace(s[i]))
		i++;
	j = ft_strlen(&s[i]) - 1;
	while (s[i] && ft_iswhitespace(s[j + i]))
		j--;
	if (!(tmp = ft_strnew(j + 1)))
		return (NULL);
	ft_strncpy(tmp, (s + i), (j + 1));
	return (tmp);
}
