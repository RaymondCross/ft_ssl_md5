/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/14 00:23:30 by rcross            #+#    #+#             */
/*   Updated: 2019/07/24 19:31:54 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_ssl.h"

void	ft_usage(char **argv)
{
	ft_printf("usage: %s [md5 | sha256 | sha224 | sha512 | sha384] "
		"[-p -q -r -s] [file name]\n"
		"-p\t echo STDIN to STDOUT and append the checksum to STDOUT\n"
		"-q\t quiet mode - only the checksum is printed. Overrides -r\n"
		"-r\t reverse the format of the output\n"
		"-s\t print a checksum of the given string\n"
		, argv[0]);
	exit(0);
}

int		main(int argc, char **argv)
{
	t_ssl		ssl;

	argc == 1 ? ft_usage(argv) : 0;
	ft_bzero(&ssl, sizeof(t_ssl));
	if ((ssl.files = malloc(sizeof(char *) * MAX_FILES)) == NULL)
		ft_usage(argv);
	if ((ssl.f_size = malloc(sizeof(uint32_t *) * MAX_FILES)) == NULL)
		ft_usage(argv);
	init_ssl(&ssl, argc, argv);
	get_input(&ssl, argv);
	if (ssl.p_size <= 0)
		ft_usage(argv);
	ssl.md5 == TRUE ? md5(&ssl) : 0;
	ssl.sha256 == TRUE ? sha256(&ssl) : 0;
	ssl.sha224 == TRUE ? sha224(&ssl) : 0;
	ssl.sha512 == TRUE ? sha512(&ssl) : 0;
	ssl.sha384 == TRUE ? sha384(&ssl) : 0;
	return (0);
}
