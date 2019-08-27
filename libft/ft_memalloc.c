/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memalloc.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/27 14:24:38 by rcross            #+#    #+#             */
/*   Updated: 2019/05/01 18:25:06 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

/*
** Allocates with malloc(3) and returns a “fresh” memory area.
** The memory allocated is initialized to 0. If the allocation fails,
** the function returns NULL
*/

#include "libft.h"

void	*ft_memalloc(size_t size)
{
	void	*tmp;

	tmp = (void *)malloc(size);
	if (!tmp)
		return (NULL);
	ft_bzero(tmp, size);
	return (tmp);
}
