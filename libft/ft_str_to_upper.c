/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_str_to_upper.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/03 17:07:16 by rcross            #+#    #+#             */
/*   Updated: 2019/06/04 16:39:28 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

/*
**	converts lowercase letters to uppercase in a string
*/

char		*ft_str_to_upper(char *str)
{
	char	*result;
	int		i;

	i = 0;
	result = str;
	while (result[i] != '\0')
	{
		if (result[i] >= 'a' && result[i] <= 'z')
			result[i] -= 32;
		i++;
	}
	return (result);
}
