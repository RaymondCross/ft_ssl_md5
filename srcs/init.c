/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   init.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/14 00:21:47 by rcross            #+#    #+#             */
/*   Updated: 2019/07/24 19:12:41 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_ssl.h"

static int	get_flag(t_ssl *ssl, char flag)
{
	int		ret;

	ret = -1;
	if (flag == 'p' && (ssl->ssl_flags.p = TRUE) == TRUE)
		ret = 0;
	else if (flag == 'q' && (ssl->ssl_flags.q = TRUE) == TRUE)
		ret = 0;
	else if (flag == 'r' && (ssl->ssl_flags.r = TRUE) == TRUE)
		ret = 0;
	else if (flag == 's' && (ssl->ssl_flags.s = TRUE) == TRUE)
		ret = 0;
	return (ret);
}

static void	get_function(t_ssl *ssl, char *param)
{
	ft_strequ(param, "md5") == 1 ? ssl->md5 = TRUE : 0;
	ft_strequ(param, "sha256") == 1 ? ssl->sha256 = TRUE : 0;
	ft_strequ(param, "sha224") == 1 ? ssl->sha224 = TRUE : 0;
	ft_strequ(param, "sha512") == 1 ? ssl->sha512 = TRUE : 0;
	ft_strequ(param, "sha384") == 1 ? ssl->sha384 = TRUE : 0;
}

/*
**	gets hashing function called, then looks for flags,
**	then copies file names passed through argv
*/

void		init_ssl(t_ssl *ssl, int argc, char **argv)
{
	int		i;
	int		x;

	i = 0;
	x = 0;
	if (++i < argc)
	{
		get_function(ssl, argv[i]);
		if (!ssl->md5 && !ssl->sha256 && !ssl->sha224
				&& !ssl->sha512 && !ssl->sha384)
			ft_usage(argv);
	}
	while (++i < argc && argv[i][0] == '-'
		&& (x = get_flag(ssl, argv[i][1])) != SEG)
		if (x == -1)
			ft_usage(argv);
	x = 0;
	while (i < argc && x < MAX_FILES)
		ssl->files[x++] = ft_strdup(argv[i++]);
	ssl->files[x] = NULL;
	if (x >= MAX_FILES)
		ft_usage(argv);
}

/*
**	reads user input if -p flag is true or no file was passed to md5,
**	or reads file to store into ssl->files (acts like get line almost)
*/

static int	get_read(int fd, char **str, uint32_t *f_size)
{
	char	*buf;
	char	*cpy;
	int		x;

	if (fd < 0)
		return (0);
	x = 0;
	*f_size = 0;
	*str = ft_memalloc(1);
	buf = malloc(101);
	cpy = NULL;
	while ((x = read(fd, buf, 100)) > 0)
	{
		cpy = malloc(sizeof(char) * (*f_size + x + 1));
		ft_memcpy(cpy, *str, *f_size);
		ft_memcpy(cpy + *f_size, buf, x);
		cpy[*f_size + x] = '\0';
		*f_size += x;
		free(*str);
		*str = cpy;
	}
	free(buf);
	(!f_size) && (**str = '\0');
	return (1);
}

/*
**	gets input if -p or no file, then gets file size and reads file
**	if given
**	-- c_stdin is used to keep track of files later on --
*/

void		get_input(t_ssl *ssl, char **argv)
{
	int		fd;
	int		i;
	int		x;

	x = 0;
	if ((ssl->to_hash = malloc(sizeof(char *) * (MAX_FILES + 1))) == NULL)
		ft_usage(argv);
	if ((i = -1) && (ssl->ssl_flags.p || ssl->files[0] == NULL)
		&& get_read(0, &ssl->to_hash[x], &ssl->f_size[x]) > 0
		&& ++ssl->p_size)
		++x;
	ssl->c_stdin = x;
	while (ssl->files[++i] != NULL && ++ssl->p_size)
	{
		if (ssl->ssl_flags.s && i == 0
			&& (ssl->f_size[x] = ft_strlen(ssl->files[i])))
			ssl->to_hash[x] = ft_strdup(ssl->files[i]);
		else if ((fd = open(ssl->files[i], O_RDONLY)) < 0)
			ssl->to_hash[x] = NULL;
		else
			get_read(fd, &ssl->to_hash[x], &ssl->f_size[x]);
		++x;
	}
	ssl->to_hash[x] = NULL;
}
