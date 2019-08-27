/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   output_64.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/14 00:23:13 by rcross            #+#    #+#             */
/*   Updated: 2019/07/24 18:53:03 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_ssl.h"

static void		p_error(t_ssl *ssl, int code, int i)
{
	code == 2 ? ft_printf("ft_ssl: sha256: %s: No such file or directory",
		ssl->files[i - ssl->c_stdin]) : 0;
	code == 3 ? ft_printf("ft_ssl: sha224: %s: No such file or directory",
		ssl->files[i - ssl->c_stdin]) : 0;
	code == 4 ? ft_printf("ft_ssl: sha512: %s: No such file or directory",
		ssl->files[i - ssl->c_stdin]) : 0;
	code == 5 ? ft_printf("ft_ssl: sha512: %s: No such file or directory",
		ssl->files[i - ssl->c_stdin]) : 0;
}

static void		p_success(t_ssl *ssl, int i, int code)
{
	if (!ssl->ssl_flags.s || i != 0 + ssl->c_stdin)
	{
		code == 2 ?
			ft_printf("SHA256 (%s) = ", ssl->files[i - ssl->c_stdin]) : 0;
		code == 3 ?
			ft_printf("SHA224 (%s) = ", ssl->files[i - ssl->c_stdin]) : 0;
		code == 4 ?
			ft_printf("SHA512 (%s) = ", ssl->files[i - ssl->c_stdin]) : 0;
		code == 5 ?
			ft_printf("SHA384 (%s) = ", ssl->files[i - ssl->c_stdin]) : 0;
	}
	else
	{
		code == 2 ?
			ft_printf("SHA256 (\"%s\") = ", ssl->files[i - ssl->c_stdin]) : 0;
		code == 3 ?
			ft_printf("SHA224 (\"%s\") = ", ssl->files[i - ssl->c_stdin]) : 0;
		code == 4 ?
			ft_printf("SHA512 (\"%s\") = ", ssl->files[i - ssl->c_stdin]) : 0;
		code == 5 ?
			ft_printf("SHA384 (\"%s\") = ", ssl->files[i - ssl->c_stdin]) : 0;
	}
}

void			output_64(t_ssl *ssl, uint64_t *hash, int i)
{
	int		code;

	ssl->sha256 ? code = 2 : 0;
	ssl->sha224 ? code = 3 : 0;
	ssl->sha512 ? code = 4 : 0;
	ssl->sha384 ? code = 5 : 0;
	if (ssl->to_hash[i] && ssl->ssl_flags.p && i == 0 && ssl->c_stdin)
		ft_printf("%s", ssl->to_hash[i]);
	if (ssl->c_stdin && ssl->to_hash[i] && i == 0)
		print_digest_64(ssl, hash, 0, -1);
	else if (ssl->to_hash[i])
	{
		!ssl->ssl_flags.q && !ssl->ssl_flags.r ? p_success(ssl, i, code) : 0;
		print_digest_64(ssl, hash, 0, -1);
		if (ssl->ssl_flags.r && ssl->ssl_flags.s &&
			!ssl->ssl_flags.q && i == 0 + ssl->c_stdin)
			ft_printf(" \"%s\"", ssl->files[i - ssl->c_stdin]);
		else if (ssl->ssl_flags.r && !ssl->ssl_flags.q)
			ft_printf(" %s", ssl->files[i - ssl->c_stdin]);
	}
	!ssl->to_hash[i] ? p_error(ssl, code, i) : 0;
	ft_printf("\n");
}
