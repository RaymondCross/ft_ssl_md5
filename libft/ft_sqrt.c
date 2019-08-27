/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_sqrt.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/03/23 23:16:40 by rcross            #+#    #+#             */
/*   Updated: 2019/03/23 23:24:14 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

/*
** Compute the non-negative square root of x. If x is negative, the function
** will return zero (0).
*/

double		ft_sqrt(double x)
{
	long	i;

	i = 1;
	if (x < 0)
		return (0);
	while (i * i < x)
		i += 1;
	return (i);
}
