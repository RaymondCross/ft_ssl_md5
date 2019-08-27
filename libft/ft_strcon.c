/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strcon.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/04 01:15:19 by rcross            #+#    #+#             */
/*   Updated: 2019/04/04 01:15:22 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strcon(char **arr, char *c)
{
	int		i;
	char	*str;
	char	*tmp;

	i = 0;
	str = ft_strnew(1);
	while (arr[i])
	{
		tmp = ft_strjoin(str, arr[i]);
		free(str);
		str = tmp;
		tmp = ft_strjoin(str, c);
		free(str);
		str = tmp;
		++i;
	}
	return (str);
}
