/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_next_line.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/03/11 15:50:39 by rcross            #+#    #+#             */
/*   Updated: 2019/05/07 22:36:52 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "get_next_line.h"

static int		get_first(char **line, char *str)
{
	int				i;

	i = -1;
	while (str[++i])
		if (str[i] == '\n')
			break ;
	*line = ft_strsub(str, 0, (size_t)i);
	return (i);
}

static char		*get_other(char *str, int i)
{
	char			*new;
	int				j;

	j = 0;
	new = ft_strnew((int)ft_strlen(str) - i);
	while (str[i + j])
	{
		new[j] = str[i + j];
		j++;
	}
	new[j] = '\0';
	ft_strdel(&str);
	return (new);
}

int				get_next_line(const int fd, char **line)
{
	static char		*tab[4864];
	char			*tmp;
	char			buf[BUFF_SIZE + 1];
	int				x;
	int				n;

	if (fd < 0 || !line || read(fd, buf, 0) < 0)
		return (-1);
	(!tab[fd]) ? tab[fd] = ft_strnew(1) : 0;
	while ((x = read(fd, buf, BUFF_SIZE)) > 0)
	{
		buf[x] = '\0';
		tmp = ft_strjoin(tab[fd], buf);
		free(tab[fd]);
		tab[fd] = tmp;
		if (ft_strchr(tab[fd], '\n'))
			break ;
	}
	if (x < BUFF_SIZE && !ft_strlen(tab[fd]))
		return (0);
	n = get_first(line, tab[fd]);
	(n < (int)ft_strlen(tab[fd])) ? tab[fd] =
	get_other(tab[fd], n + 1) : ft_bzero(tab[fd], ft_strlen(tab[fd]));
	return (1);
}
