/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstmap.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/27 14:24:07 by rcross            #+#    #+#             */
/*   Updated: 2019/03/03 15:47:13 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

t_list	*ft_lstmap(t_list *lst, t_list *(*f)(t_list *elem))
{
	t_list *head;
	t_list *current;

	current = f(lst);
	if (current == NULL)
		return (NULL);
	head = current;
	while (lst->next)
	{
		lst = lst->next;
		current->next = f(lst);
		if (current->next == NULL)
		{
			free(current->next);
			return (NULL);
		}
		current = current->next;
	}
	return (head);
}
