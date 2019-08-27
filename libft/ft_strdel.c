/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strdel.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/27 14:33:34 by rcross            #+#    #+#             */
/*   Updated: 2019/03/10 21:24:45 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

/*
** Takes as a parameter the address of a string that need to be freed with
** free(), then sets its pointer to NULL.
*/

void	ft_strdel(char **as)
{
	if (as == NULL)
		return ;
	free(*as);
	*as = NULL;
}
